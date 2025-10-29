use std::{
    collections::HashMap,
    convert::Infallible,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime},
};

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use axum::{
    body::{Body, Bytes},
    extract::State,
    http::{header::ACCEPT, HeaderMap, HeaderValue, Method, StatusCode},
    response::sse::{Event, KeepAlive},
    response::{IntoResponse, Json, Response, Sse},
    routing::{get, post},
    Router,
};
use futures_util::StreamExt;
use mcp_protocol_sdk::{
    core::{error::McpError, tool::ToolHandler},
    protocol::{
        methods,
        types::{error_codes, Content, JsonRpcError, JsonRpcMessage, RequestId, ToolResult},
    },
    server::McpServer,
};
use nix::unistd::getuid;
use rand::{distributions::Alphanumeric, Rng};
use serde_json::{json, Value};
use tokio::{
    runtime::Builder as TokioRuntimeBuilder,
    signal as tokio_signal,
    sync::{broadcast, Mutex, RwLock},
    task,
};
use tokio_stream::wrappers::BroadcastStream;
use tower_http::cors::{Any, CorsLayer};

use crate::config::{Config, DumpMode};
#[cfg(feature = "frida")]
use crate::frida_gadget::{prepare_gadget, wait_for_gadget, GadgetDeployment};
#[cfg(feature = "frida")]
use crate::ptrace::inject_library;
#[cfg(feature = "frida")]
use crate::workflow::{find_clone_thread, find_process_pid};

use crate::workflow::run_dump_workflow;

#[derive(Clone)]
struct AppState {
    server: Arc<Mutex<McpServer>>,
    sessions: Arc<RwLock<HashMap<String, Arc<SessionHandle>>>>,
}

struct SessionHandle {
    sender: broadcast::Sender<JsonRpcMessage>,
}

impl SessionHandle {
    fn new() -> Self {
        let (sender, _) = broadcast::channel(256);
        Self { sender }
    }
}

fn build_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::POST, Method::GET, Method::DELETE, Method::OPTIONS])
        .allow_headers(Any);

    Router::new()
        .route(
            "/mcp",
            post(handle_mcp_request)
                .get(handle_streamable_events)
                .delete(handle_delete_session)
                .options(handle_options),
        )
        .route("/mcp/tools/dump", post(handle_direct_dump_tool))
        .route("/health", get(handle_health))
        .with_state(state)
        .layer(cors)
}

pub fn run_mcp_server(bind: &str) -> Result<()> {
    let runtime = TokioRuntimeBuilder::new_multi_thread()
        .enable_all()
        .build()
        .context("create tokio runtime")?;
    runtime.block_on(run_async(bind.to_string()))
}

async fn run_async(bind: String) -> Result<()> {
    if !getuid().is_root() {
        println!("[MCP]  Warning: drizzleDumper server is not running as root; dumps may fail.");
    }

    let server = Arc::new(Mutex::new(McpServer::new(
        "drizzle-dumper".to_string(),
        env!("CARGO_PKG_VERSION").to_string(),
    )));
    #[cfg(feature = "frida")]
    let gadget_registry = Arc::new(Mutex::new(HashMap::new()));

    {
        let guard = server.lock().await;
        let generic_schema = dump_tool_schema(true);
        guard
            .add_tool(
                "dump_dex".to_string(),
                Some("Dump DEX/CDEX regions for a running package (auto mode)".to_string()),
                generic_schema.clone(),
                {
                    let tool = DumpTool::new(None);
                    #[cfg(feature = "frida")]
                    let tool = tool.with_gadget_store(gadget_registry.clone());
                    tool
                },
            )
            .await
            .context("register dump_dex tool")?;
        guard
            .add_tool(
                "dump_dex_ptrace".to_string(),
                Some("Dump DEX/CDEX regions using ptrace scanning".to_string()),
                dump_tool_schema(false),
                {
                    let tool = DumpTool::new(Some(DumpMode::Ptrace));
                    #[cfg(feature = "frida")]
                    let tool = tool.with_gadget_store(gadget_registry.clone());
                    tool
                },
            )
            .await
            .context("register dump_dex_ptrace tool")?;
        guard
            .add_tool(
                "dump_dex_frida".to_string(),
                Some("Dump DEX/CDEX regions via FRIDA hooks".to_string()),
                generic_schema,
                {
                    let tool = DumpTool::new(Some(DumpMode::Frida));
                    #[cfg(feature = "frida")]
                    let tool = tool.with_gadget_store(gadget_registry.clone());
                    tool
                },
            )
            .await
            .context("register dump_dex_frida tool")?;

        #[cfg(feature = "frida")]
        {
            guard
                .add_tool(
                    "prepare_frida_gadget".to_string(),
                    Some("Prepare FRIDA gadget on device".to_string()),
                    gadget_prepare_schema(),
                    PrepareGadgetTool::new(gadget_registry.clone()),
                )
                .await
                .context("register prepare_frida_gadget tool")?;
            guard
                .add_tool(
                    "inject_frida_gadget".to_string(),
                    Some("Inject prepared FRIDA gadget into target process".to_string()),
                    gadget_inject_schema(),
                    InjectGadgetTool::new(gadget_registry.clone()),
                )
                .await
                .context("register inject_frida_gadget tool")?;
            guard
                .add_tool(
                    "cleanup_frida_gadget".to_string(),
                    Some("Cleanup and remove prepared FRIDA gadget".to_string()),
                    gadget_cleanup_schema(),
                    CleanupGadgetTool::new(gadget_registry.clone()),
                )
                .await
                .context("register cleanup_frida_gadget tool")?;
        }
    }

    let state = AppState {
        server: server.clone(),
        sessions: Arc::new(RwLock::new(HashMap::new())),
    };

    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .with_context(|| format!("bind HTTP server to {bind}"))?;
    let addr: SocketAddr = listener.local_addr().context("resolve bound address")?;

    println!("[MCP]  drizzleDumper MCP server (Streamable HTTP) listening on http://{addr}/mcp");
    println!("[MCP]  Endpoints: POST /mcp, GET /mcp (SSE), DELETE /mcp (end session)");
    println!("[MCP]  Press Ctrl+C to stop the server.");

    let server_task = tokio::spawn(async move {
        if let Err(err) = axum::serve(listener, app).await {
            eprintln!("[MCP]  HTTP server error: {err}");
        }
    });

    tokio_signal::ctrl_c().await.context("wait for Ctrl+C")?;
    server_task.abort();
    if let Err(err) = server_task.await {
        if !err.is_cancelled() {
            eprintln!("[MCP]  HTTP server task ended unexpectedly: {err}");
        }
    }

    Ok(())
}

#[derive(Debug)]
struct HttpError {
    status: StatusCode,
    payload: HttpErrorPayload,
}

#[derive(Debug)]
enum HttpErrorPayload {
    Message(String),
    JsonRpc {
        id: RequestId,
        code: i32,
        message: String,
    },
}

impl HttpError {
    fn message(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            payload: HttpErrorPayload::Message(message.into()),
        }
    }

    fn jsonrpc(status: StatusCode, id: RequestId, code: i32, message: impl Into<String>) -> Self {
        Self {
            status,
            payload: HttpErrorPayload::JsonRpc {
                id,
                code,
                message: message.into(),
            },
        }
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        match self.payload {
            HttpErrorPayload::Message(message) => {
                let body = Json(json!({ "error": message }));
                (self.status, body).into_response()
            }
            HttpErrorPayload::JsonRpc { id, code, message } => {
                let error = JsonRpcError::error(id, code, message, None);
                (self.status, Json(JsonRpcMessage::Error(error))).into_response()
            }
        }
    }
}

async fn handle_mcp_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, HttpError> {
    if body_is_blank(body.as_ref()) {
        return Err(HttpError::jsonrpc(
            StatusCode::BAD_REQUEST,
            RequestId::Null,
            error_codes::PARSE_ERROR,
            "Request body is empty",
        ));
    }

    let wants_event_stream = accept_includes_event_stream(&headers);

    let parsed_single: Result<JsonRpcMessage, _> = serde_json::from_slice(&body);
    let messages: Vec<JsonRpcMessage> = match parsed_single {
        Ok(message) => vec![message],
        Err(_) => serde_json::from_slice(&body).map_err(|err| {
            HttpError::jsonrpc(
                StatusCode::BAD_REQUEST,
                RequestId::Null,
                error_codes::PARSE_ERROR,
                format!("Failed to parse JSON body: {err}"),
            )
        })?,
    };

    let mut session_id = extract_session_id(&headers);
    let mut session_handle = if let Some(ref id) = session_id {
        Some(
            get_session_handle(&state, id)
                .await
                .ok_or_else(|| HttpError::message(StatusCode::NOT_FOUND, "Unknown MCP session"))?,
        )
    } else {
        None
    };
    let mut responses: Vec<JsonRpcMessage> = Vec::new();

    for message in messages {
        match message {
            JsonRpcMessage::Request(request) => {
                let is_initialize = request.method == methods::INITIALIZE;

                if is_initialize {
                    let (new_id, handle) = create_session(&state).await;
                    session_id = Some(new_id);
                    session_handle = Some(handle);
                }

                let handle =
                    ensure_session_handle(&state, &mut session_handle, &mut session_id).await?;
                let request_id = request.id.clone();
                let response = {
                    let server = state.server.clone();
                    let guard = server.lock().await;
                    guard.handle_request(request).await
                }
                .map_err(|err| {
                    let (code, message) = map_mcp_error(&err);
                    HttpError::jsonrpc(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        request_id.clone(),
                        code,
                        message,
                    )
                })?;

                let message = JsonRpcMessage::Response(response);
                if handle.sender.send(message.clone()).is_err() {
                    tracing::debug!(
                        "session {} has no active SSE listeners",
                        session_id.as_deref().unwrap_or("<unknown>")
                    );
                }
                responses.push(message);
            }
            JsonRpcMessage::Notification(notification) => {
                let handle =
                    ensure_session_handle(&state, &mut session_handle, &mut session_id).await?;
                let message = JsonRpcMessage::Notification(notification);
                let _ = handle.sender.send(message);
            }
            JsonRpcMessage::Response(response) => {
                let handle =
                    ensure_session_handle(&state, &mut session_handle, &mut session_id).await?;
                let message = JsonRpcMessage::Response(response);
                let _ = handle.sender.send(message);
            }
            JsonRpcMessage::Error(error) => {
                let handle =
                    ensure_session_handle(&state, &mut session_handle, &mut session_id).await?;
                let message = JsonRpcMessage::Error(error);
                let _ = handle.sender.send(message);
            }
        }
    }

    let mut response = if responses.is_empty() {
        Response::builder()
            .status(StatusCode::ACCEPTED)
            .body(Body::empty())
            .map_err(|_| {
                HttpError::message(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to build response body",
                )
            })?
    } else if wants_event_stream {
        let stream = tokio_stream::iter(responses.clone().into_iter().map(|message| {
            serde_json::to_string(&message)
                .map(|json| Ok::<Event, Infallible>(Event::default().data(json)))
                .unwrap_or_else(|err| {
                    tracing::error!("Failed to serialize JSON-RPC message: {err}");
                    Ok::<Event, Infallible>(Event::default().data("{}"))
                })
        }));
        Sse::new(stream)
            .keep_alive(
                KeepAlive::new()
                    .interval(Duration::from_secs(30))
                    .text("keep-alive"),
            )
            .into_response()
    } else if responses.len() == 1 {
        Json(responses.into_iter().next().unwrap()).into_response()
    } else {
        Json(responses).into_response()
    };

    if let Some(ref id) = session_id {
        response.headers_mut().insert(
            "Mcp-Session-Id",
            HeaderValue::from_str(id).map_err(|_| {
                HttpError::message(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Invalid session identifier",
                )
            })?,
        );
    }

    Ok(response)
}

async fn handle_streamable_events(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, HttpError> {
    if !accept_includes_event_stream(&headers) {
        return Err(HttpError::message(
            StatusCode::NOT_ACCEPTABLE,
            "Accept header must include text/event-stream",
        ));
    }

    let session_id = extract_session_id(&headers).ok_or_else(|| {
        HttpError::message(StatusCode::BAD_REQUEST, "Missing Mcp-Session-Id header")
    })?;
    let handle = get_session_handle(&state, &session_id)
        .await
        .ok_or_else(|| HttpError::message(StatusCode::NOT_FOUND, "Unknown MCP session"))?;

    let receiver = handle.sender.subscribe();
    let stream = BroadcastStream::new(receiver).filter_map(|msg| async move {
        match msg {
            Ok(message) => match serde_json::to_string(&message) {
                Ok(json) => Some(Ok::<Event, Infallible>(Event::default().data(json))),
                Err(err) => {
                    tracing::error!("Failed to serialize SSE message: {err}");
                    None
                }
            },
            Err(_) => None,
        }
    });

    let mut response = Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(30))
                .text("keep-alive"),
        )
        .into_response();
    response.headers_mut().insert(
        "Mcp-Session-Id",
        HeaderValue::from_str(&session_id).map_err(|_| {
            HttpError::message(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Invalid session identifier",
            )
        })?,
    );
    Ok(response)
}

async fn handle_delete_session(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<StatusCode, HttpError> {
    let session_id = extract_session_id(&headers).ok_or_else(|| {
        HttpError::message(StatusCode::BAD_REQUEST, "Missing Mcp-Session-Id header")
    })?;

    if remove_session(&state, &session_id).await {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(HttpError::message(
            StatusCode::NOT_FOUND,
            "Unknown MCP session",
        ))
    }
}

async fn handle_direct_dump_tool(
    State(state): State<AppState>,
    body: Bytes,
) -> Result<Json<ToolResult>, (StatusCode, Json<Value>)> {
    if body_is_blank(body.as_ref()) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Request body is empty" })),
        ));
    }

    let payload: Value = serde_json::from_slice(&body).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": format!("Invalid JSON body: {err}") })),
        )
    })?;

    let args = payload
        .as_object()
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "JSON body must be an object" })),
            )
        })?
        .clone()
        .into_iter()
        .collect::<HashMap<_, _>>();

    if !args.contains_key("package") {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Missing required field `package`" })),
        ));
    }

    let guard = state.server.lock().await;
    let result = guard
        .call_tool("dump_dex", Some(args))
        .await
        .map_err(|err| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": err.to_string() })),
            )
        })?;

    Ok(Json(result))
}

async fn handle_options() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn handle_health() -> Json<Value> {
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    Json(json!({
        "status": "ok",
        "timestamp": timestamp,
    }))
}

fn body_is_blank(body: &[u8]) -> bool {
    body.iter().all(|byte| byte.is_ascii_whitespace())
}

fn accept_includes_event_stream(headers: &HeaderMap) -> bool {
    headers
        .get(ACCEPT)
        .and_then(|value| value.to_str().ok())
        .map(|v| {
            v.split(',')
                .any(|item| item.trim().eq_ignore_ascii_case("text/event-stream"))
        })
        .unwrap_or(false)
}

fn extract_session_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get("Mcp-Session-Id")
        .and_then(|value| value.to_str().ok())
        .map(|s| s.to_string())
}

fn map_mcp_error(err: &McpError) -> (i32, String) {
    let message = err.to_string();
    let code = match err {
        McpError::Validation(_) => error_codes::INVALID_PARAMS,
        McpError::Protocol(_) => error_codes::INVALID_REQUEST,
        McpError::ToolNotFound(_) => error_codes::TOOL_NOT_FOUND,
        McpError::ResourceNotFound(_) => error_codes::RESOURCE_NOT_FOUND,
        McpError::PromptNotFound(_) => error_codes::PROMPT_NOT_FOUND,
        _ => error_codes::INTERNAL_ERROR,
    };
    (code, message)
}

async fn ensure_session_handle(
    state: &AppState,
    session_handle: &mut Option<Arc<SessionHandle>>,
    session_id: &mut Option<String>,
) -> Result<Arc<SessionHandle>, HttpError> {
    if let Some(handle) = session_handle.as_ref() {
        return Ok(handle.clone());
    }

    if let Some(ref id) = session_id {
        if let Some(handle) = get_session_handle(state, id).await {
            *session_handle = Some(handle.clone());
            return Ok(handle);
        }
        return Err(HttpError::message(
            StatusCode::NOT_FOUND,
            "Unknown MCP session",
        ));
    }

    Err(HttpError::message(
        StatusCode::BAD_REQUEST,
        "Missing Mcp-Session-Id header; run initialize first",
    ))
}

async fn create_session(state: &AppState) -> (String, Arc<SessionHandle>) {
    loop {
        let candidate = generate_random_id();
        let handle = Arc::new(SessionHandle::new());
        let mut sessions = state.sessions.write().await;
        if sessions.contains_key(&candidate) {
            continue;
        }
        sessions.insert(candidate.clone(), handle.clone());
        return (candidate, handle);
    }
}

async fn get_session_handle(state: &AppState, id: &str) -> Option<Arc<SessionHandle>> {
    let sessions = state.sessions.read().await;
    sessions.get(id).cloned()
}

async fn remove_session(state: &AppState, id: &str) -> bool {
    let mut sessions = state.sessions.write().await;
    sessions.remove(id).is_some()
}

fn generate_random_id() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

struct DumpTool {
    lock: Mutex<()>,
    forced_mode: Option<DumpMode>,
    #[cfg(feature = "frida")]
    gadget_store: Option<Arc<Mutex<HashMap<String, GadgetDeployment>>>>,
}

#[async_trait]
impl ToolHandler for DumpTool {
    async fn call(&self, arguments: HashMap<String, Value>) -> Result<ToolResult, McpError> {
        let _guard = self.lock.lock().await;

        let package = arguments
            .get("package")
            .and_then(Value::as_str)
            .ok_or_else(|| McpError::validation("missing required string parameter `package`"))?
            .to_string();

        let mut cfg = config_from_args(&arguments)?;
        if let Some(mode) = self.forced_mode {
            cfg.dump_mode = mode;
        }
        #[cfg(feature = "frida")]
        if let Some(store) = &self.gadget_store {
            if let Some(id) = cfg.frida.gadget_id.clone() {
                let (library_path, config_path, port, keep) = {
                    let guard = store.lock().await;
                    let deployment = guard
                        .get(&id)
                        .ok_or_else(|| McpError::validation(format!("unknown gadget id `{id}`")))?;
                    (
                        deployment.library_path.clone(),
                        Some(deployment.config_path.clone()),
                        deployment.port,
                        deployment.keep_files(),
                    )
                };
                cfg.frida.gadget_enabled = true;
                cfg.frida.gadget_library_path = Some(library_path);
                cfg.frida.gadget_config_path = config_path;
                cfg.frida.gadget_port = Some(port);
                cfg.frida.gadget_keep_files = keep;
            }
        }
        let result = task::spawn_blocking(move || run_dump_workflow(&package, &cfg))
            .await
            .map_err(|err| McpError::internal(format!("dump task join error: {err}")))?;

        let dump_mode_label = match cfg.dump_mode {
            DumpMode::Ptrace => "ptrace",
            DumpMode::Frida => "frida",
        };
        let dumps = result.map_err(|err| McpError::internal(err.to_string()))?;
        let files: Vec<String> = dumps.iter().map(|p| p.display().to_string()).collect();
        let count = files.len();
        let message = if files.is_empty() {
            "No dex/cdex regions dumped. Check server logs for details.".to_string()
        } else {
            let list = files.join("\n- ");
            format!("Dumped {count} file(s):\n- {list}")
        };

        let mut structured = json!({
            "files": files,
            "count": count,
            "mode": dump_mode_label,
        });
        #[cfg(feature = "frida")]
        {
            if dump_mode_label == "frida" {
                structured["frida"] = json!({
                    "remote": cfg.frida.remote,
                    "usb": cfg.frida.use_usb,
                    "spawn": cfg.frida.spawn,
                    "script_path": cfg.frida.script_path.as_ref().map(|p| p.display().to_string()),
                    "chunk_size": cfg.frida.chunk_size,
                    "gadget": {
                        "enabled": cfg.frida.gadget_enabled,
                        "port": cfg.frida.gadget_port,
                        "keep_files": cfg.frida.gadget_keep_files,
                        "library_path": cfg.frida.gadget_library_path.as_ref().map(|p| p.display().to_string()),
                        "config_path": cfg.frida.gadget_config_path.as_ref().map(|p| p.display().to_string()),
                        "deployment_id": cfg.frida.gadget_id.clone()
                    }
                });
            }
        }

        Ok(ToolResult {
            content: vec![Content::text(message)],
            is_error: None,
            structured_content: Some(structured),
            meta: None,
        })
    }
}

impl DumpTool {
    fn new(forced_mode: Option<DumpMode>) -> Self {
        Self {
            lock: Mutex::new(()),
            forced_mode,
            #[cfg(feature = "frida")]
            gadget_store: None,
        }
    }

    #[cfg(feature = "frida")]
    fn with_gadget_store(mut self, store: Arc<Mutex<HashMap<String, GadgetDeployment>>>) -> Self {
        self.gadget_store = Some(store);
        self
    }
}

#[cfg(feature = "frida")]
struct GadgetInfo {
    library_path: PathBuf,
    config_path: Option<PathBuf>,
    port: u16,
}

#[cfg(feature = "frida")]
impl GadgetInfo {
    fn from_deployment(dep: &GadgetDeployment) -> Self {
        Self {
            library_path: dep.library_path.clone(),
            config_path: Some(dep.config_path.clone()),
            port: dep.port,
        }
    }

    fn library_display(&self) -> String {
        self.library_path.display().to_string()
    }

    fn config_display(&self) -> String {
        self.config_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "-".to_string())
    }
}

#[cfg(feature = "frida")]
struct PrepareGadgetTool {
    registry: Arc<Mutex<HashMap<String, GadgetDeployment>>>,
}

#[cfg(feature = "frida")]
impl PrepareGadgetTool {
    fn new(registry: Arc<Mutex<HashMap<String, GadgetDeployment>>>) -> Self {
        Self { registry }
    }
}

#[cfg(feature = "frida")]
#[async_trait]
impl ToolHandler for PrepareGadgetTool {
    async fn call(&self, arguments: HashMap<String, Value>) -> Result<ToolResult, McpError> {
        let cfg = gadget_config_from_args(&arguments)?;
        let deployment = task::spawn_blocking(move || prepare_gadget(&cfg))
            .await
            .map_err(|err| McpError::internal(format!("prepare gadget task failed: {err}")))?
            .map_err(|err| McpError::internal(err.to_string()))?;

        let info = GadgetInfo::from_deployment(&deployment);
        let id = generate_random_id();

        {
            let mut guard = self.registry.lock().await;
            guard.insert(id.clone(), deployment);
        }

        let message = format!(
            "Prepared FRIDA gadget `{}` at {} (config {}, port {})",
            id,
            info.library_display(),
            info.config_display(),
            info.port
        );

        Ok(ToolResult {
            content: vec![Content::text(message)],
            is_error: None,
            structured_content: Some(json!({
                "deployment_id": id,
                "library_path": info.library_path,
                "config_path": info.config_path,
                "port": info.port,
            })),
            meta: None,
        })
    }
}

#[cfg(feature = "frida")]
struct InjectGadgetTool {
    registry: Arc<Mutex<HashMap<String, GadgetDeployment>>>,
}

#[cfg(feature = "frida")]
impl InjectGadgetTool {
    fn new(registry: Arc<Mutex<HashMap<String, GadgetDeployment>>>) -> Self {
        Self { registry }
    }
}

#[cfg(feature = "frida")]
#[async_trait]
impl ToolHandler for InjectGadgetTool {
    async fn call(&self, arguments: HashMap<String, Value>) -> Result<ToolResult, McpError> {
        let deployment_id = arguments
            .get("deployment_id")
            .and_then(Value::as_str)
            .ok_or_else(|| McpError::validation("missing `deployment_id`"))?
            .to_string();

        let info = {
            let guard = self.registry.lock().await;
            let deployment = guard.get(&deployment_id).ok_or_else(|| {
                McpError::validation(format!("unknown gadget id `{deployment_id}`"))
            })?;
            GadgetInfo::from_deployment(deployment)
        };

        let pid_arg = arguments.get("pid").map(|v| as_u64("pid", v)).transpose()?;
        let package_arg = arguments
            .get("package")
            .and_then(Value::as_str)
            .map(|s| s.to_string());
        if pid_arg.is_none() && package_arg.is_none() {
            return Err(McpError::validation(
                "`inject_frida_gadget` requires either `pid` or `package`",
            ));
        }

        let timeout_secs = arguments
            .get("timeout")
            .map(|v| as_u64("timeout", v))
            .transpose()?
            .unwrap_or(10);

        let library_path = info.library_path.clone();
        let config_path = info.config_path.clone();
        let port = info.port;
        let package_for_spawn = package_arg.clone();
        let join_result = task::spawn_blocking(move || -> Result<()> {
            let pid = if let Some(pid) = pid_arg {
                pid as i32
            } else {
                let package = package_for_spawn.as_deref().unwrap();
                find_process_pid(package)?.ok_or_else(|| anyhow!("process {package} not found"))?
            };
            let tid =
                find_clone_thread(pid)?.ok_or_else(|| anyhow!("no thread found for pid {pid}"))?;

            let prev_env = std::env::var_os("FRIDA_GADGET_CONFIG");
            if let Some(config_path) = config_path.as_deref() {
                std::env::set_var("FRIDA_GADGET_CONFIG", config_path);
            }

            inject_library(tid, library_path.as_path())?;
            wait_for_gadget(port, Duration::from_secs(timeout_secs))?;

            match (config_path.as_deref(), prev_env) {
                (_, Some(prev)) => std::env::set_var("FRIDA_GADGET_CONFIG", prev),
                (Some(_), None) => std::env::remove_var("FRIDA_GADGET_CONFIG"),
                _ => {}
            }

            Ok(())
        })
        .await
        .map_err(|err| McpError::internal(format!("inject gadget task failed: {err}")))?;

        join_result
            .map_err(|err| McpError::internal(format!("inject gadget task failed: {err}")))?;

        let target_desc = package_arg
            .as_deref()
            .map(|p| p.to_string())
            .unwrap_or_else(|| format!("pid {}", pid_arg.unwrap()));

        Ok(ToolResult {
            content: vec![Content::text(format!(
                "Injected gadget `{}` into {target_desc}; listening on {}",
                deployment_id, info.port
            ))],
            is_error: None,
            structured_content: Some(json!({
                "deployment_id": deployment_id,
                "target": target_desc,
                "port": info.port,
            })),
            meta: None,
        })
    }
}

#[cfg(feature = "frida")]
struct CleanupGadgetTool {
    registry: Arc<Mutex<HashMap<String, GadgetDeployment>>>,
}

#[cfg(feature = "frida")]
impl CleanupGadgetTool {
    fn new(registry: Arc<Mutex<HashMap<String, GadgetDeployment>>>) -> Self {
        Self { registry }
    }
}

#[cfg(feature = "frida")]
#[async_trait]
impl ToolHandler for CleanupGadgetTool {
    async fn call(&self, arguments: HashMap<String, Value>) -> Result<ToolResult, McpError> {
        let id = arguments
            .get("deployment_id")
            .and_then(Value::as_str)
            .ok_or_else(|| McpError::validation("missing `deployment_id`"))?
            .to_string();

        let removed = {
            let mut guard = self.registry.lock().await;
            guard.remove(&id)
        };

        match removed {
            Some(deployment) => {
                deployment.cleanup();
                Ok(ToolResult {
                    content: vec![Content::text(format!("Cleaned up FRIDA gadget `{}`", id))],
                    is_error: None,
                    structured_content: Some(json!({
                        "deployment_id": id,
                        "removed": true
                    })),
                    meta: None,
                })
            }
            None => Err(McpError::validation(format!("unknown gadget id `{id}`"))),
        }
    }
}

impl Default for DumpTool {
    fn default() -> Self {
        Self::new(None)
    }
}

fn config_from_args(arguments: &HashMap<String, Value>) -> Result<Config, McpError> {
    let mut cfg = Config::default();

    if let Some(wait) = arguments.get("wait_time") {
        cfg.wait_time = as_f64("wait_time", wait)?;
    }
    if let Some(out) = arguments.get("out_dir") {
        cfg.out_dir = PathBuf::from(as_string("out_dir", out)?);
    }
    if let Some(dump_all) = arguments.get("dump_all") {
        cfg.dump_all = as_bool("dump_all", dump_all)?;
    }
    if let Some(fix) = arguments.get("fix_header") {
        cfg.fix_header = as_bool("fix_header", fix)?;
    }
    if let Some(step) = arguments.get("scan_step") {
        cfg.scan_step = as_u64("scan_step", step)?;
    }
    if let Some(min_size) = arguments
        .get("min_size")
        .or_else(|| arguments.get("min_region"))
    {
        cfg.min_region = as_u64("min_size", min_size)?;
    }
    if let Some(max_size) = arguments
        .get("max_size")
        .or_else(|| arguments.get("max_region"))
    {
        cfg.max_region = as_u64("max_size", max_size)?;
    }
    if let Some(min_dump) = arguments.get("min_dump_size") {
        cfg.min_dump_size = as_u64("min_dump_size", min_dump)?.max(0x70);
    }
    if let Some(signal) = arguments.get("signal_trigger") {
        cfg.signal_trigger = as_bool("signal_trigger", signal)?;
    }
    if let Some(watch) = arguments.get("watch_maps") {
        cfg.watch_maps = as_bool("watch_maps", watch)?;
    }
    if let Some(threshold) = arguments.get("stage_threshold") {
        cfg.stage_threshold = Some(as_u64("stage_threshold", threshold)? as usize);
        cfg.watch_maps = true;
    }
    if let Some(patterns) = arguments.get("map_patterns") {
        match patterns {
            Value::String(s) => add_pattern(&mut cfg.map_patterns, s),
            Value::Array(items) => {
                for item in items {
                    let s = item.as_str().ok_or_else(|| {
                        McpError::validation("`map_patterns` entries must be strings")
                    })?;
                    add_pattern(&mut cfg.map_patterns, s);
                }
            }
            _ => {
                return Err(McpError::validation(
                    "`map_patterns` must be a string or array of strings",
                ))
            }
        }
        if !cfg.map_patterns.is_empty() {
            cfg.watch_maps = true;
        }
    }

    if let Some(mode) = arguments.get("mode") {
        let value = as_string("mode", mode)?;
        match value.to_ascii_lowercase().as_str() {
            "frida" => cfg.dump_mode = DumpMode::Frida,
            "ptrace" => cfg.dump_mode = DumpMode::Ptrace,
            other => {
                return Err(McpError::validation(format!(
                    "`mode` must be `ptrace` or `frida`, got {other}"
                )))
            }
        }
    }
    if let Some(flag) = arguments.get("frida") {
        if as_bool("frida", flag)? {
            cfg.dump_mode = DumpMode::Frida;
        }
    }
    if let Some(remote) = arguments.get("frida_remote") {
        cfg.frida.remote = Some(as_string("frida_remote", remote)?);
    }
    if let Some(usb) = arguments.get("frida_usb") {
        cfg.frida.use_usb = as_bool("frida_usb", usb)?;
    }
    if let Some(spawn) = arguments.get("frida_spawn") {
        cfg.frida.spawn = as_bool("frida_spawn", spawn)?;
    }
    if let Some(attach) = arguments.get("frida_attach") {
        if as_bool("frida_attach", attach)? {
            cfg.frida.spawn = false;
        }
    }
    if let Some(no_resume) = arguments.get("frida_no_resume") {
        if as_bool("frida_no_resume", no_resume)? {
            cfg.frida.resume_after_spawn = false;
        }
    }
    if let Some(script) = arguments.get("frida_script") {
        cfg.frida.script_path = Some(PathBuf::from(as_string("frida_script", script)?));
    }
    if let Some(chunk) = arguments.get("frida_chunk") {
        let parsed = as_u64("frida_chunk", chunk)? as usize;
        cfg.frida.chunk_size = parsed.max(4096);
    }
    if let Some(val) = arguments.get("frida_gadget") {
        if as_bool("frida_gadget", val)? {
            cfg.frida.gadget_enabled = true;
        }
    }
    if let Some(port) = arguments.get("frida_gadget_port") {
        cfg.frida.gadget_port = Some(as_u64("frida_gadget_port", port)? as u16);
    }
    if let Some(keep) = arguments.get("frida_gadget_keep") {
        cfg.frida.gadget_keep_files = as_bool("frida_gadget_keep", keep)?;
    }
    if let Some(path) = arguments.get("frida_gadget_path") {
        cfg.frida.gadget_library_path = Some(PathBuf::from(as_string("frida_gadget_path", path)?));
    }
    if let Some(path) = arguments.get("frida_gadget_config") {
        cfg.frida.gadget_config_path = Some(PathBuf::from(as_string("frida_gadget_config", path)?));
    }
    if let Some(id) = arguments.get("frida_gadget_id") {
        cfg.frida.gadget_id = Some(as_string("frida_gadget_id", id)?);
    }

    let implicit_frida = cfg.frida.remote.is_some()
        || cfg.frida.use_usb
        || cfg.frida.script_path.is_some()
        || cfg.frida.gadget_enabled
        || !cfg.frida.spawn
        || !cfg.frida.resume_after_spawn;
    if implicit_frida && cfg.dump_mode != DumpMode::Frida {
        cfg.dump_mode = DumpMode::Frida;
    }

    Ok(cfg)
}

#[cfg(feature = "frida")]
fn gadget_config_from_args(arguments: &HashMap<String, Value>) -> Result<Config, McpError> {
    let mut params = arguments.clone();
    params
        .entry("package".to_string())
        .or_insert_with(|| Value::String("__gadget__".to_string()));
    let mut cfg = config_from_args(&params)?;
    cfg.dump_mode = DumpMode::Frida;
    cfg.frida.gadget_enabled = true;
    Ok(cfg)
}

fn dump_tool_schema(include_frida: bool) -> Value {
    use serde_json::Map;

    let mut properties = Map::new();
    properties.insert("package".into(), json!({"type": "string"}));
    properties.insert("wait_time".into(), json!({"type": "number"}));
    properties.insert("out_dir".into(), json!({"type": "string"}));
    properties.insert("dump_all".into(), json!({"type": "boolean"}));
    properties.insert("fix_header".into(), json!({"type": "boolean"}));
    properties.insert("scan_step".into(), json!({"type": "integer", "minimum": 1}));
    properties.insert("min_size".into(), json!({"type": "integer", "minimum": 1}));
    properties.insert("max_size".into(), json!({"type": "integer", "minimum": 1}));
    properties.insert(
        "min_dump_size".into(),
        json!({"type": "integer", "minimum": 1}),
    );
    properties.insert("signal_trigger".into(), json!({"type": "boolean"}));
    properties.insert("watch_maps".into(), json!({"type": "boolean"}));
    properties.insert(
        "stage_threshold".into(),
        json!({"type": "integer", "minimum": 1}),
    );
    properties.insert(
        "map_patterns".into(),
        json!({
            "oneOf": [
                {"type": "string"},
                {"type": "array", "items": {"type": "string"}}
            ]
        }),
    );

    if include_frida {
        properties.insert(
            "mode".into(),
            json!({"type": "string", "enum": ["ptrace", "frida"]}),
        );
        properties.insert(
            "frida".into(),
            json!({"type": "boolean", "description": "Shorthand to force FRIDA mode without specifying \"mode\": \"frida\"."}),
        );
        properties.insert(
            "frida_remote".into(),
            json!({"type": "string", "description": "Connect to an existing frida-server at <host:port> instead of spawning/gadget injection."}),
        );
        properties.insert(
            "frida_usb".into(),
            json!({"type": "boolean", "description": "Prefer the first USB device reported by Frida when selecting the target device."}),
        );
        properties.insert(
            "frida_spawn".into(),
            json!({"type": "boolean", "description": "Request cold start (spawn) of the package. Gadget 模式会自动忽略该选项。"}),
        );
        properties.insert(
            "frida_attach".into(),
            json!({"type": "boolean", "description": "Force attach to an already running process (equivalent to CLI --frida-attach)."}),
        );
        properties.insert(
            "frida_no_resume".into(),
            json!({"type": "boolean", "description": "当 spawn 模式下保持进程暂停，直到脚本加载完毕。"}),
        );
        properties.insert(
            "frida_script".into(),
            json!({"type": "string", "description": "自定义 agent 脚本的绝对路径；缺省时使用内置 Dex Hook 脚本。"}),
        );
        properties.insert(
            "frida_chunk".into(),
            json!({"type": "integer", "minimum": 4096, "description": "Dex 分块传输大小（字节），默认 16 MiB。"}),
        );
        properties.insert(
            "frida_gadget".into(),
            json!({"type": "boolean", "description": "启用自动部署 FRIDA Gadget；为 true 时会忽略 spawn 并自动使用 attach 模式。"}),
        );
        properties.insert(
            "frida_gadget_port".into(),
            json!({"type": "integer", "minimum": 1, "maximum": 65535, "description": "监听端口；不指定时随机选择 28000-40000 区间。"}),
        );
        properties.insert(
            "frida_gadget_keep".into(),
            json!({"type": "boolean", "description": "任务结束后是否保留生成的 Gadget 目录/文件。"}),
        );
        properties.insert(
            "frida_gadget_path".into(),
            json!({"type": "string", "description": "自带的 frida-gadget.so 文件路径；若未提供则使用内置 bundle（需启用 frida-gadget-bundle）。"}),
        );
        properties.insert(
            "frida_gadget_config".into(),
            json!({"type": "string", "description": "自定义 gadget 配置文件路径；不提供时会自动生成仅监听 127.0.0.1:<port> 的模板。"}),
        );
        properties.insert(
            "frida_gadget_id".into(),
            json!({"type": "string", "description": "复用 `prepare_frida_gadget` 产生的 deployment_id，跳过文件重新生成。"}),
        );
    }

    let mut schema = Map::new();
    schema.insert("type".into(), json!("object"));
    schema.insert("properties".into(), Value::Object(properties));
    schema.insert("required".into(), json!(["package"]));

    Value::Object(schema)
}

#[cfg(feature = "frida")]
fn gadget_prepare_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "out_dir": {
                "type": "string",
                "description": "设备上用于存放 Gadget 运行目录的根路径，默认 /data/local/tmp/drizzle_gadget。"
            },
            "frida_gadget_port": {
                "type": "integer",
                "minimum": 1,
                "maximum": 65535,
                "description": "监听端口；若为空则自动随机。"
            },
            "frida_gadget_keep": {
                "type": "boolean",
                "description": "保留生成的临时目录，便于后续手动注入或排查。"
            },
            "frida_gadget_path": {
                "type": "string",
                "description": "已有的 frida-gadget.so 路径；为空时写入内置镜像。"
            },
            "frida_gadget_config": {
                "type": "string",
                "description": "外部配置 JSON；未提供时会生成默认的 script 监听配置。"
            }
        }
    })
}

#[cfg(feature = "frida")]
fn gadget_inject_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "deployment_id": {
                "type": "string",
                "description": "`prepare_frida_gadget` 返回的 ID，用于复用已生成的 Gadget。"
            },
            "package": {
                "type": "string",
                "description": "目标进程包名；pid 与 package 至少提供其一。"
            },
            "pid": {
                "type": "integer",
                "minimum": 1,
                "description": "目标进程 PID。"
            },
            "timeout": {
                "type": "integer",
                "minimum": 1,
                "description": "等待 Gadget 监听端口就绪的秒数，默认 10。"
            }
        },
        "required": ["deployment_id"]
    })
}

#[cfg(feature = "frida")]
fn gadget_cleanup_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "deployment_id": {
                "type": "string",
                "description": "要清理的 Gadget 部署 ID（与 prepare/inject 共用）。"
            }
        },
        "required": ["deployment_id"]
    })
}

fn add_pattern(target: &mut Vec<String>, value: &str) {
    let trimmed = value.trim();
    if !trimmed.is_empty() {
        target.push(trimmed.to_ascii_lowercase());
    }
}

fn as_bool(name: &str, value: &Value) -> Result<bool, McpError> {
    value
        .as_bool()
        .ok_or_else(|| McpError::validation(format!("`{name}` must be a boolean")))
}

fn as_u64(name: &str, value: &Value) -> Result<u64, McpError> {
    value
        .as_u64()
        .or_else(|| value.as_f64().map(|v| v.max(0.0) as u64))
        .ok_or_else(|| McpError::validation(format!("`{name}` must be a positive number")))
}

fn as_f64(name: &str, value: &Value) -> Result<f64, McpError> {
    value
        .as_f64()
        .ok_or_else(|| McpError::validation(format!("`{name}` must be a number")))
}

fn as_string(name: &str, value: &Value) -> Result<String, McpError> {
    value
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| McpError::validation(format!("`{name}` must be a string")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{self, Body},
        http::{
            header::{ACCEPT, CONTENT_TYPE},
            Method, Request,
        },
    };
    use serde_json::{json, Value as JsonValue};
    use std::path::PathBuf;
    use tokio::sync::{Mutex, RwLock};
    use tower::ServiceExt;

    fn make_app(server: Arc<Mutex<McpServer>>) -> Router {
        build_router(AppState {
            server,
            sessions: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    fn initialize_body() -> Body {
        Body::from(
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {
                        "name": "test-client",
                        "version": "0.0.1"
                    }
                }
            }))
            .unwrap(),
        )
    }

    #[tokio::test]
    async fn empty_body_returns_json_parse_error() {
        let server = Arc::new(Mutex::new(McpServer::new(
            "test-server".to_string(),
            "0.0.1".to_string(),
        )));
        let app = make_app(server);
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/mcp")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from("   "))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let content_type = response.headers().get(CONTENT_TYPE).unwrap();
        assert_eq!(content_type, "application/json");

        let body_bytes = body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: JsonValue = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(json["jsonrpc"], "2.0");
        assert_eq!(json["id"], JsonValue::Null);
        assert_eq!(json["error"]["code"], error_codes::PARSE_ERROR);
        assert!(json["error"]["message"].as_str().unwrap().contains("empty"));
    }

    #[tokio::test]
    async fn invalid_json_returns_parse_error() {
        let server = Arc::new(Mutex::new(McpServer::new(
            "test-server".to_string(),
            "0.0.1".to_string(),
        )));
        let app = make_app(server);
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/mcp")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from("{bad json"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body_bytes = body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: JsonValue = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(json["error"]["code"], error_codes::PARSE_ERROR);
        assert!(json["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Failed to parse JSON"));
    }

    #[tokio::test]
    async fn initialize_returns_session_header() {
        let server = Arc::new(Mutex::new(McpServer::new(
            "test-server".to_string(),
            "0.0.1".to_string(),
        )));
        let app = make_app(server);
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/mcp")
                    .header(CONTENT_TYPE, "application/json")
                    .body(initialize_body())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let session_header = response.headers().get("Mcp-Session-Id").unwrap();
        assert!(!session_header.is_empty());

        let bytes = body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: JsonValue = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["jsonrpc"], "2.0");
        assert!(json["result"].is_object());
    }

    #[tokio::test]
    async fn tools_list_without_session_is_rejected() {
        let server = Arc::new(Mutex::new(McpServer::new(
            "test-server".to_string(),
            "0.0.1".to_string(),
        )));
        let app = make_app(server);
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/mcp")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "jsonrpc": "2.0",
                            "id": 42,
                            "method": "tools/list",
                            "params": {}
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: JsonValue = serde_json::from_slice(&body).unwrap();
        assert!(json["error"]
            .as_str()
            .unwrap()
            .contains("Missing Mcp-Session-Id"));
    }

    #[tokio::test]
    async fn tool_call_succeeds_after_initialize() {
        let server = Arc::new(Mutex::new(McpServer::new(
            "test-server".to_string(),
            "0.0.1".to_string(),
        )));
        let captured: Arc<Mutex<Option<HashMap<String, serde_json::Value>>>> =
            Arc::new(Mutex::new(None));
        {
            let guard = server.lock().await;
            guard
                .add_tool(
                    "dump_dex".to_string(),
                    Some("dummy".to_string()),
                    json!({
                        "type": "object",
                        "properties": { "package": {"type": "string"} },
                        "required": ["package"]
                    }),
                    DummyTool {
                        captured: captured.clone(),
                    },
                )
                .await
                .unwrap();
        }

        let app = make_app(server);
        let init_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/mcp")
                    .header(CONTENT_TYPE, "application/json")
                    .body(initialize_body())
                    .unwrap(),
            )
            .await
            .unwrap();
        let session_id = init_response
            .headers()
            .get("Mcp-Session-Id")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/mcp")
                    .header(CONTENT_TYPE, "application/json")
                    .header("Mcp-Session-Id", session_id)
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "jsonrpc": "2.0",
                            "id": 2,
                            "method": "tools/call",
                            "params": {
                                "name": "dump_dex",
                                "arguments": {
                                    "package": "com.example.app"
                                }
                            }
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: JsonValue = serde_json::from_slice(&body).unwrap();
        assert!(json["result"].is_object());
        assert!(captured.lock().await.is_some());
    }

    #[tokio::test]
    async fn get_requires_event_stream_accept() {
        let server = Arc::new(Mutex::new(McpServer::new(
            "test-server".to_string(),
            "0.0.1".to_string(),
        )));
        let app = make_app(server);
        let init_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/mcp")
                    .header(CONTENT_TYPE, "application/json")
                    .body(initialize_body())
                    .unwrap(),
            )
            .await
            .unwrap();
        let session_id = init_response
            .headers()
            .get("Mcp-Session-Id")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        let missing_accept = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/mcp")
                    .header("Mcp-Session-Id", &session_id)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing_accept.status(), StatusCode::NOT_ACCEPTABLE);

        let ok_response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/mcp")
                    .header("Mcp-Session-Id", session_id)
                    .header(ACCEPT, "text/event-stream")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ok_response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn direct_endpoint_invokes_tool() {
        let server = Arc::new(Mutex::new(McpServer::new(
            "test-server".to_string(),
            "0.0.1".to_string(),
        )));

        let captured: Arc<Mutex<Option<HashMap<String, serde_json::Value>>>> =
            Arc::new(Mutex::new(None));
        {
            let guard = server.lock().await;
            guard
                .add_tool(
                    "dump_dex".to_string(),
                    Some("dummy".to_string()),
                    json!({
                        "type": "object",
                        "properties": { "package": {"type": "string"} },
                        "required": ["package"]
                    }),
                    DummyTool {
                        captured: captured.clone(),
                    },
                )
                .await
                .unwrap();
        }

        let app = make_app(server);
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/mcp/tools/dump")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "package": "com.example.app",
                            "dump_all": true
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(captured.lock().await.is_some());
    }

    #[test]
    fn schema_without_frida_does_not_include_mode() {
        let schema = dump_tool_schema(false);
        assert!(schema["properties"].get("package").is_some());
        assert!(schema["properties"].get("mode").is_none());
        assert!(schema["properties"].get("frida_remote").is_none());
    }

    #[test]
    fn config_builder_supports_frida_mode() {
        let mut args = HashMap::new();
        args.insert("mode".to_string(), json!("frida"));
        args.insert("frida_remote".to_string(), json!("127.0.0.1:27042"));
        args.insert("frida_usb".to_string(), json!(true));
        args.insert("frida_attach".to_string(), json!(true));
        args.insert("frida_no_resume".to_string(), json!(true));
        args.insert("frida_script".to_string(), json!("/tmp/agent.js"));
        args.insert("frida_chunk".to_string(), json!(65536));
        args.insert("frida_gadget".to_string(), json!(true));
        args.insert("frida_gadget_port".to_string(), json!(34567));
        args.insert("frida_gadget_keep".to_string(), json!(true));
        args.insert("frida_gadget_path".to_string(), json!("/tmp/gadget.so"));
        args.insert(
            "frida_gadget_config".to_string(),
            json!("/tmp/gadget.config"),
        );

        let cfg = config_from_args(&args).expect("parse config");
        assert_eq!(cfg.dump_mode, DumpMode::Frida);
        assert_eq!(cfg.frida.remote.as_deref(), Some("127.0.0.1:27042"));
        assert!(cfg.frida.use_usb);
        assert!(!cfg.frida.spawn);
        assert!(!cfg.frida.resume_after_spawn);
        assert_eq!(cfg.frida.script_path, Some(PathBuf::from("/tmp/agent.js")));
        assert_eq!(cfg.frida.chunk_size, 65536);
        assert!(cfg.frida.gadget_enabled);
        assert_eq!(cfg.frida.gadget_port, Some(34_567));
        assert!(cfg.frida.gadget_keep_files);
        assert_eq!(
            cfg.frida.gadget_library_path,
            Some(PathBuf::from("/tmp/gadget.so"))
        );
        assert_eq!(
            cfg.frida.gadget_config_path,
            Some(PathBuf::from("/tmp/gadget.config"))
        );
    }

    struct DummyTool {
        captured: Arc<Mutex<Option<HashMap<String, serde_json::Value>>>>,
    }

    #[async_trait]
    impl ToolHandler for DummyTool {
        async fn call(
            &self,
            arguments: HashMap<String, serde_json::Value>,
        ) -> Result<ToolResult, McpError> {
            let mut guard = self.captured.lock().await;
            *guard = Some(arguments);
            Ok(ToolResult {
                content: vec![Content::text("ok".to_string())],
                is_error: Some(false),
                structured_content: None,
                meta: None,
            })
        }
    }
}
