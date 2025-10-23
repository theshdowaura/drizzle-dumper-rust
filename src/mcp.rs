use std::{
    collections::HashMap,
    convert::Infallible,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result};
use async_trait::async_trait;
use axum::{
    body::Bytes,
    extract::State,
    http::{Method, StatusCode},
    response::sse::{Event, KeepAlive},
    response::{Json, Sse},
    routing::{get, post},
    Router,
};
use futures_util::StreamExt;
use mcp_protocol_sdk::{
    client::McpClient,
    core::{error::McpError, tool::ToolHandler},
    protocol::types::{
        error_codes, Content, JsonRpcError, JsonRpcMessage, JsonRpcNotification, JsonRpcRequest,
        RequestId, ToolResult,
    },
    server::McpServer,
<<<<<<< HEAD
=======
    transport::http::HttpClientTransport,
>>>>>>> f55a884 (Add remote MCP client support to CLI)
};
use nix::unistd::getuid;
use serde_json::{json, Value};
use tokio::{
    runtime::Builder as TokioRuntimeBuilder,
    signal as tokio_signal,
    sync::{broadcast, Mutex},
    task,
};
use tokio_stream::wrappers::BroadcastStream;
use tower_http::cors::{Any, CorsLayer};

use crate::config::Config;
use crate::workflow::run_dump_workflow;

#[derive(Clone)]
struct AppState {
    server: Arc<Mutex<McpServer>>,
    notifier: broadcast::Sender<JsonRpcNotification>,
}

fn build_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::POST, Method::GET, Method::OPTIONS])
        .allow_headers(Any);

    Router::new()
        .route("/mcp", post(handle_mcp_request).options(handle_options))
        .route("/mcp/notify", post(handle_notification))
        .route("/mcp/events", get(handle_sse_events))
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
<<<<<<< HEAD

    {
        let guard = server.lock().await;
        guard
            .add_tool(
                "dump_dex".to_string(),
                Some("Dump DEX/CDEX regions for a running package".to_string()),
                json!({
                    "type": "object",
                    "properties": {
                        "package": {"type": "string"},
                        "wait_time": {"type": "number"},
                        "out_dir": {"type": "string"},
                        "dump_all": {"type": "boolean"},
                        "fix_header": {"type": "boolean"},
                        "scan_step": {"type": "integer", "minimum": 1},
                        "min_size": {"type": "integer", "minimum": 1},
                        "max_size": {"type": "integer", "minimum": 1},
                        "min_dump_size": {"type": "integer", "minimum": 1},
                        "signal_trigger": {"type": "boolean"},
                        "watch_maps": {"type": "boolean"},
                        "stage_threshold": {"type": "integer", "minimum": 1},
                        "map_patterns": {
                            "oneOf": [
                                {"type": "string"},
                                {"type": "array", "items": {"type": "string"}}
                            ]
                        }
                    },
                    "required": ["package"],
                }),
                DumpTool::default(),
            )
            .await
            .context("register dump_dex tool")?;
    }

    let (notifier, _) = broadcast::channel(256);
    let state = AppState {
        server: server.clone(),
        notifier,
    };

    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .with_context(|| format!("bind HTTP server to {bind}"))?;
    let addr: SocketAddr = listener.local_addr().context("resolve bound address")?;

    println!("[MCP]  drizzleDumper MCP server listening on http://{addr}");
    println!("[MCP]  Endpoints: POST /mcp, POST /mcp/notify, GET /mcp/events (SSE)");
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
=======

    {
        let guard = server.lock().await;
        guard
            .add_tool(
                "dump_dex".to_string(),
                Some("Dump DEX/CDEX regions for a running package".to_string()),
                json!({
                    "type": "object",
                    "properties": {
                        "package": {"type": "string"},
                        "wait_time": {"type": "number"},
                        "out_dir": {"type": "string"},
                        "dump_all": {"type": "boolean"},
                        "fix_header": {"type": "boolean"},
                        "scan_step": {"type": "integer", "minimum": 1},
                        "min_size": {"type": "integer", "minimum": 1},
                        "max_size": {"type": "integer", "minimum": 1},
                        "min_dump_size": {"type": "integer", "minimum": 1},
                        "signal_trigger": {"type": "boolean"},
                        "watch_maps": {"type": "boolean"},
                        "stage_threshold": {"type": "integer", "minimum": 1},
                        "map_patterns": {
                            "oneOf": [
                                {"type": "string"},
                                {"type": "array", "items": {"type": "string"}}
                            ]
                        }
                    },
                    "required": ["package"],
                }),
                DumpTool::default(),
            )
            .await
            .context("register dump_dex tool")?;
    }

    let (notifier, _) = broadcast::channel(256);
    let state = AppState {
        server: server.clone(),
        notifier,
    };

    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .with_context(|| format!("bind HTTP server to {bind}"))?;
    let addr: SocketAddr = listener.local_addr().context("resolve bound address")?;

    println!("[MCP]  drizzleDumper MCP server listening on http://{addr}");
    println!("[MCP]  Endpoints: POST /mcp, POST /mcp/notify, GET /mcp/events (SSE)");
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

pub fn call_dump_tool_remote(base_url: &str, package: &str, cfg: &Config) -> Result<ToolResult> {
    let runtime = TokioRuntimeBuilder::new_current_thread()
        .enable_all()
        .build()
        .context("create tokio runtime for remote MCP call")?;

    runtime.block_on(call_dump_tool_remote_async(base_url, package, cfg))
}

async fn call_dump_tool_remote_async(
    base_url: &str,
    package: &str,
    cfg: &Config,
) -> Result<ToolResult> {
    let (request_url, sse_url) = build_remote_urls(base_url);

    let transport = HttpClientTransport::new(request_url, Some(sse_url))
        .await
        .context("connect HTTP transport")?;

    let mut client = McpClient::new(
        "drizzle-dumper-cli".to_string(),
        env!("CARGO_PKG_VERSION").to_string(),
    );

    client
        .connect(transport)
        .await
        .context("initialize MCP client")?;

    let arguments = config_to_tool_arguments(package, cfg);
    let result = client
        .call_tool("dump_dex".to_string(), Some(arguments))
        .await
        .context("call dump_dex tool")?;

    // Best-effort cleanup; ignore disconnect errors.
    let _ = client.disconnect().await;

    Ok(result)
}

fn build_remote_urls(base_url: &str) -> (String, String) {
    let trimmed = base_url.trim_end_matches('/');
    if trimmed.ends_with("/mcp") {
        let call = trimmed.to_string();
        let sse = format!("{}/events", trimmed);
        (call, sse)
    } else {
        (
            format!("{}/mcp", trimmed),
            format!("{}/mcp/events", trimmed),
        )
    }
}

fn config_to_tool_arguments(package: &str, cfg: &Config) -> HashMap<String, Value> {
    let mut map = HashMap::new();
    map.insert("package".to_string(), Value::String(package.to_string()));
    map.insert("wait_time".to_string(), json!(cfg.wait_time));
    map.insert(
        "out_dir".to_string(),
        Value::String(cfg.out_dir.to_string_lossy().into_owned()),
    );
    map.insert("dump_all".to_string(), json!(cfg.dump_all));
    map.insert("fix_header".to_string(), json!(cfg.fix_header));
    map.insert("scan_step".to_string(), json!(cfg.scan_step));
    map.insert("min_size".to_string(), json!(cfg.min_region));
    map.insert("max_size".to_string(), json!(cfg.max_region));
    map.insert("min_dump_size".to_string(), json!(cfg.min_dump_size));
    map.insert("signal_trigger".to_string(), json!(cfg.signal_trigger));
    map.insert("watch_maps".to_string(), json!(cfg.watch_maps));
    if let Some(threshold) = cfg.stage_threshold {
        map.insert("stage_threshold".to_string(), json!(threshold));
    }
    if !cfg.map_patterns.is_empty() {
        map.insert("map_patterns".to_string(), json!(cfg.map_patterns));
    }
    map
}

async fn handle_mcp_request(
    State(state): State<AppState>,
    body: Bytes,
) -> Result<Json<JsonRpcMessage>, (StatusCode, Json<JsonRpcMessage>)> {
    if body_is_blank(body.as_ref()) {
        return Err(json_rpc_error(
            StatusCode::BAD_REQUEST,
            serde_json::Value::Null,
            error_codes::PARSE_ERROR,
            "Request body is empty",
        ));
    }

    let request: JsonRpcRequest = serde_json::from_slice(&body).map_err(|err| {
        json_rpc_error(
            StatusCode::BAD_REQUEST,
            serde_json::Value::Null,
            error_codes::PARSE_ERROR,
            format!("Failed to parse JSON request body: {err}"),
        )
    })?;
    let request_id = request.id.clone();

    let result = {
        let guard = state.server.lock().await;
        guard.handle_request(request).await
    };

    match result {
        Ok(response) => Ok(Json(JsonRpcMessage::Response(response))),
        Err(err) => {
            let (code, message) = map_mcp_error(&err);
            Err(json_rpc_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                request_id,
                code,
                message,
            ))
        }
    }
}

async fn handle_notification(
    State(state): State<AppState>,
    body: Bytes,
) -> Result<StatusCode, (StatusCode, Json<JsonRpcMessage>)> {
    if body_is_blank(body.as_ref()) {
        return Ok(StatusCode::NO_CONTENT);
    }

    let notification: JsonRpcNotification = serde_json::from_slice(&body).map_err(|err| {
        json_rpc_error(
            StatusCode::BAD_REQUEST,
            serde_json::Value::Null,
            error_codes::PARSE_ERROR,
            format!("Failed to parse JSON notification body: {err}"),
        )
    })?;

    // Broadcast to SSE listeners; ignore if nobody is listening.
    let _ = state.notifier.send(notification);

    Ok(StatusCode::OK)
}

async fn handle_sse_events(
    State(state): State<AppState>,
) -> Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>> {
    let receiver = state.notifier.subscribe();
    let stream = BroadcastStream::new(receiver).filter_map(|msg| async move {
        match msg {
            Ok(notification) => match serde_json::to_string(&notification) {
                Ok(json) => Some(Ok(Event::default().data(json))),
                Err(err) => {
                    tracing::error!("Failed to serialize notification: {err}");
                    None
                }
            },
            Err(_) => None,
        }
    });

    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(30))
            .text("keep-alive"),
    )
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

fn json_rpc_error(
    status: StatusCode,
    id: RequestId,
    code: i32,
    message: impl Into<String>,
) -> (StatusCode, Json<JsonRpcMessage>) {
    let error = JsonRpcError::error(id, code, message.into(), None);
    (status, Json(JsonRpcMessage::Error(error)))
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
>>>>>>> f55a884 (Add remote MCP client support to CLI)
}

async fn handle_mcp_request(
    State(state): State<AppState>,
    body: Bytes,
) -> Result<Json<JsonRpcMessage>, (StatusCode, Json<JsonRpcMessage>)> {
    if body_is_blank(body.as_ref()) {
        return Err(json_rpc_error(
            StatusCode::BAD_REQUEST,
            serde_json::Value::Null,
            error_codes::PARSE_ERROR,
            "Request body is empty",
        ));
    }

    let request: JsonRpcRequest = serde_json::from_slice(&body).map_err(|err| {
        json_rpc_error(
            StatusCode::BAD_REQUEST,
            serde_json::Value::Null,
            error_codes::PARSE_ERROR,
            format!("Failed to parse JSON request body: {err}"),
        )
    })?;
    let request_id = request.id.clone();

    let result = {
        let guard = state.server.lock().await;
        guard.handle_request(request).await
    };

    match result {
        Ok(response) => Ok(Json(JsonRpcMessage::Response(response))),
        Err(err) => {
            let (code, message) = map_mcp_error(&err);
            Err(json_rpc_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                request_id,
                code,
                message,
            ))
        }
    }
}

async fn handle_notification(
    State(state): State<AppState>,
    body: Bytes,
) -> Result<StatusCode, (StatusCode, Json<JsonRpcMessage>)> {
    if body_is_blank(body.as_ref()) {
        return Ok(StatusCode::NO_CONTENT);
    }

    let notification: JsonRpcNotification = serde_json::from_slice(&body).map_err(|err| {
        json_rpc_error(
            StatusCode::BAD_REQUEST,
            serde_json::Value::Null,
            error_codes::PARSE_ERROR,
            format!("Failed to parse JSON notification body: {err}"),
        )
    })?;

    // Broadcast to SSE listeners; ignore if nobody is listening.
    let _ = state.notifier.send(notification);

    Ok(StatusCode::OK)
}

async fn handle_sse_events(
    State(state): State<AppState>,
) -> Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>> {
    let receiver = state.notifier.subscribe();
    let stream = BroadcastStream::new(receiver).filter_map(|msg| async move {
        match msg {
            Ok(notification) => match serde_json::to_string(&notification) {
                Ok(json) => Some(Ok(Event::default().data(json))),
                Err(err) => {
                    tracing::error!("Failed to serialize notification: {err}");
                    None
                }
            },
            Err(_) => None,
        }
    });

    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(30))
            .text("keep-alive"),
    )
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

fn json_rpc_error(
    status: StatusCode,
    id: RequestId,
    code: i32,
    message: impl Into<String>,
) -> (StatusCode, Json<JsonRpcMessage>) {
    let error = JsonRpcError::error(id, code, message.into(), None);
    (status, Json(JsonRpcMessage::Error(error)))
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

#[derive(Default)]
struct DumpTool {
    lock: Mutex<()>,
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

        let cfg = config_from_args(&arguments)?;
        let result = task::spawn_blocking(move || run_dump_workflow(&package, &cfg))
            .await
            .map_err(|err| McpError::internal(format!("dump task join error: {err}")))?;

        let dumps = result.map_err(|err| McpError::internal(err.to_string()))?;
        let message = if dumps.is_empty() {
            "No dex/cdex regions dumped. Check server logs for details.".to_string()
        } else {
            let list = dumps
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join("\n- ");
            format!("Dumped {} file(s):\n- {}", dumps.len(), list)
        };

        Ok(ToolResult {
            content: vec![Content::text(message)],
            is_error: None,
            structured_content: None,
            meta: None,
        })
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

    Ok(cfg)
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
        http::{header::CONTENT_TYPE, Method, Request},
    };
<<<<<<< HEAD
    use serde_json::Value as JsonValue;
=======
    use crate::config::Config;
    use serde_json::{json, Value as JsonValue};
    use std::io::ErrorKind;
    use std::path::PathBuf;
>>>>>>> f55a884 (Add remote MCP client support to CLI)
    use tokio::sync::{broadcast, Mutex};
    use tower::ServiceExt;

    fn make_test_app() -> Router {
        let server = Arc::new(Mutex::new(McpServer::new(
            "test-server".to_string(),
            "0.0.1".to_string(),
        )));
        let (notifier, _) = broadcast::channel(8);
        build_router(AppState { server, notifier })
    }

    #[tokio::test]
    async fn empty_body_returns_json_parse_error() {
        let app = make_test_app();
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
        let app = make_test_app();
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
<<<<<<< HEAD
=======

    #[tokio::test]
    async fn remote_call_invokes_dump_tool() {
        let server = Arc::new(Mutex::new(McpServer::new(
            "test-remote".to_string(),
            "0.1.0".to_string(),
        )));

        let captured: Arc<Mutex<Option<HashMap<String, serde_json::Value>>>> =
            Arc::new(Mutex::new(None));
        {
            let guard = server.lock().await;
            guard
                .add_tool(
                    "dump_dex".to_string(),
                    Some("Dummy tool".to_string()),
                    json!({
                        "type": "object",
                        "properties": {
                            "package": {"type": "string"}
                        },
                        "required": ["package"]
                    }),
                    DummyTool {
                        captured: captured.clone(),
                    },
                )
                .await
                .unwrap();
        }

        let (notifier, _) = broadcast::channel(8);
        let app = build_router(AppState {
            server: server.clone(),
            notifier,
        });
        let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(err) if err.kind() == ErrorKind::PermissionDenied => {
                eprintln!("skipping remote_call_invokes_dump_tool: {err}");
                return;
            }
            Err(err) => panic!("failed to bind test server: {err}"),
        };
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            if let Err(err) = axum::serve(listener, app).await {
                panic!("test server error: {err}");
            }
        });

        let mut cfg = Config::default();
        cfg.wait_time = 1.25;
        cfg.dump_all = true;
        cfg.fix_header = true;
        cfg.scan_step = 2048;
        cfg.min_region = 0x2000;
        cfg.max_region = 0x4000;
        cfg.min_dump_size = 0x180;
        cfg.signal_trigger = true;
        cfg.watch_maps = true;
        cfg.stage_threshold = Some(3);
        cfg.map_patterns.push("classes.dex".into());
        cfg.out_dir = PathBuf::from("/data/local/tmp/tests");

        let result = call_dump_tool_remote_async(
            &format!("http://{addr}"),
            "com.example.app",
            &cfg,
        )
        .await
        .unwrap();

        assert_eq!(result.is_error, Some(false));
        assert!(result
            .structured_content
            .as_ref()
            .and_then(|v| v.get("paths"))
            .is_some());

        let stored = captured.lock().await.clone().unwrap();
        assert_eq!(
            stored
                .get("package")
                .and_then(|v| v.as_str())
                .unwrap(),
            "com.example.app"
        );
        assert_eq!(stored.get("wait_time").unwrap(), &json!(1.25));
        assert_eq!(stored.get("dump_all").unwrap(), &json!(true));
        assert_eq!(stored.get("watch_maps").unwrap(), &json!(true));
        assert_eq!(
            stored.get("map_patterns").unwrap(),
            &json!(["classes.dex"])
        );
        assert_eq!(stored.get("stage_threshold").unwrap(), &json!(3));

        server_task.abort();
        let _ = server_task.await;
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
            assert_eq!(
                arguments
                    .get("package")
                    .and_then(|v| v.as_str())
                    .unwrap(),
                "com.example.app"
            );
            let mut guard = self.captured.lock().await;
            *guard = Some(arguments);
            Ok(ToolResult {
                content: vec![Content::text("remote ok".to_string())],
                is_error: Some(false),
                structured_content: Some(json!({"paths": ["/tmp/foo.dex"]})),
                meta: None,
            })
        }
    }
>>>>>>> f55a884 (Add remote MCP client support to CLI)
}
