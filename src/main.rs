use anyhow::Result;
use clap::Parser;
use drizzle_dumper::cli::{Cli, Commands};
use drizzle_dumper::{run_dump_workflow, run_mcp_server};
use nix::unistd::getuid;

fn main() -> Result<()> {
    println!("[>>>]  This is drizzleDumper (Rust) [<<<]");
    println!("[>>>]    rewritten by Codex       [<<<]");
    println!("[>>>]        2025.10              [<<<]");

    let cli = Cli::parse();

    match cli.command {
        Commands::McpServer(opts) => run_mcp_server(&opts.bind),
        Commands::Dump(opts) => {
            if !getuid().is_root() {
                println!("[*]  Device Not root!");
                return Ok(());
            }

            let cfg = opts.to_config();
            run_dump_workflow(&opts.package, &cfg)?;
            Ok(())
        }
    }
}
