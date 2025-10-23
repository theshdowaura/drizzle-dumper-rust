use anyhow::{anyhow, Result};
use drizzle_dumper::config::{parse_config_from_index, print_usage};
use drizzle_dumper::{call_dump_tool_remote, parse_config, run_dump_workflow, run_mcp_server};
use mcp_protocol_sdk::protocol::types::{ContentBlock, ToolResult};
use serde_json::to_string_pretty;
use nix::unistd::getuid;

fn main() -> Result<()> {
    println!("[>>>]  This is drizzleDumper (Rust) [<<<]");
    println!("[>>>]    rewritten by Codex       [<<<]");
    println!("[>>>]        2025.10              [<<<]");

    let args: Vec<String> = std::env::args().collect();
    if args.len() <= 1 {
        print_usage();
        return Ok(());
    }

    if args[1] == "--mcp-server" {
        let bind = args.get(2).map(|s| s.as_str()).unwrap_or("0.0.0.0:45831");
        return run_mcp_server(bind);
    }

    if args[1] == "--mcp-call" {
        if args.len() < 4 {
            print_usage();
            return Ok(());
        }

        let endpoint = &args[2];
        let package = &args[3];
        let cfg = parse_config_from_index(&args, 3)?;
        let result = call_dump_tool_remote(endpoint, package, &cfg)?;
        render_tool_result(&result)?;
        if result.is_error.unwrap_or(false) {
            return Err(anyhow!("remote dump_dex call reported an error"));
        }
        return Ok(());
    }

    if !getuid().is_root() {
        println!("[*]  Device Not root!");
        return Ok(());
    }

    let package_name = &args[1];
    let cfg = parse_config(&args)?;
    let _ = run_dump_workflow(package_name, &cfg)?;
    Ok(())
}

fn render_tool_result(result: &ToolResult) -> Result<()> {
    for block in &result.content {
        match block {
            ContentBlock::Text { text, .. } => println!("{text}"),
            ContentBlock::Image { .. } => println!("[remote] Received image content (omitted)"),
            ContentBlock::Audio { .. } => println!("[remote] Received audio content (omitted)"),
            ContentBlock::ResourceLink { uri, name, .. } => {
                println!("[remote] Resource: {name} -> {uri}");
            }
            ContentBlock::Resource { .. } => {
                println!("[remote] Embedded resource content received (omitted)");
            }
        }
    }

    if let Some(structured) = &result.structured_content {
        if !structured.is_null() {
            match to_string_pretty(structured) {
                Ok(pretty) => println!("[remote] Structured content:\n{pretty}"),
                Err(_) => println!("[remote] Structured content: {structured}"),
            }
        }
    }

    Ok(())
}
