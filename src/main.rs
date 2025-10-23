use anyhow::Result;
use drizzle_dumper::config::print_usage;
use drizzle_dumper::{parse_config, run_dump_workflow, run_mcp_server};
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

    if !getuid().is_root() {
        println!("[*]  Device Not root!");
        return Ok(());
    }

    let package_name = &args[1];
    let cfg = parse_config(&args)?;
    let _ = run_dump_workflow(package_name, &cfg)?;
    Ok(())
}
