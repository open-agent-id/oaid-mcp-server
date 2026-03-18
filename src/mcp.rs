//! Minimal MCP (Model Context Protocol) server over stdio.
//!
//! Implements JSON-RPC 2.0 over line-delimited stdio, handling:
//! - `initialize` — return server info and capabilities
//! - `tools/list` — return available tool definitions
//! - `tools/call` — dispatch to tool handlers

use serde_json::{json, Value};
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::tools;

/// A tool definition for the MCP tools/list response.
struct ToolDef {
    name: &'static str,
    description: &'static str,
    input_schema: Value,
}

/// All 8 MCP tools with their schemas.
fn tool_definitions() -> Vec<ToolDef> {
    vec![
        ToolDef {
            name: "oaid_whoami",
            description: "Return this agent's DID and public info. No private key included.",
            input_schema: json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
        },
        ToolDef {
            name: "oaid_sign_request",
            description: "Sign an HTTP request. Returns auth headers to attach to the request.",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "method": { "type": "string", "description": "HTTP method (GET, POST, etc.)" },
                    "url": { "type": "string", "description": "Full request URL" },
                    "body": { "type": "string", "description": "Optional request body string" }
                },
                "required": ["method", "url"]
            }),
        },
        ToolDef {
            name: "oaid_check_credit",
            description: "Check the credit score of any agent by DID.",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "did": { "type": "string", "description": "The DID to look up (e.g. did:oaid:base:0x...)" }
                },
                "required": ["did"]
            }),
        },
        ToolDef {
            name: "oaid_lookup_agent",
            description: "Look up agent information by DID. Returns only safe public fields.",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "did": { "type": "string", "description": "The DID to look up" }
                },
                "required": ["did"]
            }),
        },
        ToolDef {
            name: "oaid_send_message",
            description: "Send a signed message to another agent.",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "to_did": { "type": "string", "description": "Recipient agent DID" },
                    "body": { "type": "object", "description": "Message body (arbitrary JSON object)" },
                    "msg_type": { "type": "string", "description": "Optional message type label (default: 'default')" }
                },
                "required": ["to_did", "body"]
            }),
        },
        ToolDef {
            name: "oaid_get_messages",
            description: "Get messages addressed to this agent. Authenticates automatically.",
            input_schema: json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
        },
        ToolDef {
            name: "oaid_send_encrypted_message",
            description: "Send an end-to-end encrypted message to another agent. Uses NaCl box (X25519-XSalsa20-Poly1305).",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "to_did": { "type": "string", "description": "Recipient agent DID" },
                    "plaintext": { "type": "string", "description": "The plaintext message to encrypt and send" }
                },
                "required": ["to_did", "plaintext"]
            }),
        },
        ToolDef {
            name: "oaid_list_agents",
            description: "List all agent credential files found in ~/.oaid/ directory. Shows DIDs and names only, never private keys.",
            input_schema: json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
        },
    ]
}

/// Build the JSON array of tool definitions for tools/list.
fn tools_list_json() -> Value {
    let defs = tool_definitions();
    let tools: Vec<Value> = defs
        .into_iter()
        .map(|t| {
            json!({
                "name": t.name,
                "description": t.description,
                "inputSchema": t.input_schema,
            })
        })
        .collect();
    json!(tools)
}

/// Build a JSON-RPC success response.
fn rpc_response(id: &Value, result: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result,
    })
}

/// Build a JSON-RPC error response.
fn rpc_error(id: &Value, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message,
        },
    })
}

/// Run the MCP server, reading JSON-RPC from stdin and writing responses to stdout.
pub async fn run_server() -> Result<(), Box<dyn std::error::Error>> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let reader = BufReader::new(stdin);
    let mut lines = reader.lines();

    while let Some(line) = lines.next_line().await? {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let request: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue, // Skip malformed JSON
        };

        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let method = request
            .get("method")
            .and_then(|m| m.as_str())
            .unwrap_or("");

        let response = match method {
            "initialize" => {
                rpc_response(
                    &id,
                    json!({
                        "protocolVersion": "2024-11-05",
                        "capabilities": {
                            "tools": {}
                        },
                        "serverInfo": {
                            "name": "oaid-mcp-server",
                            "version": env!("CARGO_PKG_VERSION"),
                        }
                    }),
                )
            }

            "notifications/initialized" => {
                // Client acknowledgement — no response needed
                continue;
            }

            "tools/list" => {
                rpc_response(
                    &id,
                    json!({
                        "tools": tools_list_json(),
                    }),
                )
            }

            "tools/call" => {
                let params = request.get("params").cloned().unwrap_or(json!({}));
                let tool_name = params
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("");
                let arguments = params.get("arguments").cloned().unwrap_or(json!({}));

                let result = tools::dispatch(tool_name, &arguments).await;

                match result {
                    Ok(value) => rpc_response(
                        &id,
                        json!({
                            "content": [{
                                "type": "text",
                                "text": serde_json::to_string_pretty(&value).unwrap_or_default(),
                            }],
                        }),
                    ),
                    Err(err) => rpc_response(
                        &id,
                        json!({
                            "content": [{
                                "type": "text",
                                "text": format!("Error: {err}"),
                            }],
                            "isError": true,
                        }),
                    ),
                }
            }

            "ping" => rpc_response(&id, json!({})),

            _ => {
                // Notifications (no id) are silently ignored
                if id.is_null() {
                    continue;
                }
                rpc_error(&id, -32601, &format!("method not found: {method}"))
            }
        };

        let mut out = serde_json::to_string(&response)?;
        out.push('\n');
        stdout.write_all(out.as_bytes()).await?;
        stdout.flush().await?;
    }

    Ok(())
}
