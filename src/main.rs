//! oaid-mcp-server — MCP server for AI agents to use Open Agent ID credentials securely.
//!
//! The private key NEVER leaves this server process. All signing and encryption
//! happens internally; the AI agent only receives DIDs, public info, and results.

mod credential;
mod mcp;
mod tools;

use std::env;
use std::process;

fn print_help() {
    eprintln!(
        "oaid-mcp-server {version}
MCP server for AI agents to use Open Agent ID credentials securely.

USAGE:
    oaid-mcp-server                    Run MCP server (stdio)
    oaid-mcp-server encrypt <file>     Encrypt a credential file
    oaid-mcp-server help               Show this help message

ENVIRONMENT VARIABLES:
    OAID_CREDENTIAL_FILE    Path to credential file (required for server mode)
    OAID_PASSPHRASE         Passphrase for encrypted credentials (optional, prompts if unset)
    OAID_CREDENTIAL_DIR     Directory to scan for agent credentials (default: ~/.oaid/)

SECURITY:
    The private key never leaves this process. All signing and encryption
    happens inside the server. The AI agent only sees DIDs, public info,
    and operation results.",
        version = env!("CARGO_PKG_VERSION"),
    );
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    // Subcommand dispatch
    if args.len() >= 2 {
        match args[1].as_str() {
            "help" | "--help" | "-h" => {
                print_help();
                return;
            }
            "encrypt" => {
                if args.len() < 3 {
                    eprintln!("Usage: oaid-mcp-server encrypt <file>");
                    process::exit(1);
                }
                match credential::encrypt_file(&args[2]) {
                    Ok(out_path) => {
                        eprintln!("Encrypted credential saved to: {out_path}");
                        eprintln!("You can now delete the plaintext file.");
                    }
                    Err(e) => {
                        eprintln!("Error: {e}");
                        process::exit(1);
                    }
                }
                return;
            }
            other => {
                eprintln!("Unknown command: {other}");
                eprintln!("Run 'oaid-mcp-server help' for usage.");
                process::exit(1);
            }
        }
    }

    // Default: run MCP server
    let cred_path = env::var("OAID_CREDENTIAL_FILE").unwrap_or_default();
    if cred_path.is_empty() {
        eprintln!(
            "oaid-mcp-server: OAID_CREDENTIAL_FILE environment variable is not set.\n\
             Point it at your agent credential file (.json or .enc)."
        );
        process::exit(1);
    }

    match credential::load(&cred_path) {
        Ok(cred) => {
            eprintln!("oaid-mcp-server: loaded credential for {}", cred.did);
            tools::init_credential(cred);
        }
        Err(e) => {
            eprintln!("oaid-mcp-server: failed to load credential: {e}");
            process::exit(1);
        }
    }

    if let Err(e) = mcp::run_server().await {
        eprintln!("oaid-mcp-server: server error: {e}");
        process::exit(1);
    }
}
