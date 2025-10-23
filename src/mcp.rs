use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use async_trait::async_trait;
use mcp_protocol_sdk::{
    core::{error::McpError, tool::ToolHandler},
    protocol::types::{Content, ToolResult},
    server::McpServer,
    transport::websocket::WebSocketServerTransport,
};
use nix::unistd::getuid;
use serde_json::{json, Value};
use tokio::runtime::Builder as TokioRuntimeBuilder;
use tokio::signal as tokio_signal;
use tokio::{sync::Mutex, task};

use crate::config::Config;
use crate::workflow::run_dump_workflow;

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

    let mut server = McpServer::new(
        "drizzle-dumper".to_string(),
        env!("CARGO_PKG_VERSION").to_string(),
    );

    server
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

    let transport = WebSocketServerTransport::new(bind.as_str());
    server
        .start(transport)
        .await
        .context("start MCP websocket server")?;

    println!("[MCP]  drizzleDumper MCP server listening on ws://{bind}");
    println!("[MCP]  Press Ctrl+C to stop the server.");
    tokio_signal::ctrl_c().await.context("wait for Ctrl+C")?;

    server.stop().await.context("stop MCP server")?;
    Ok(())
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
