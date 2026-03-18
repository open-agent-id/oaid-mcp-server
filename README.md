# oaid-mcp-server

MCP (Model Context Protocol) server for AI agents to securely interact with [Open Agent ID](https://openagentid.org). A single binary that handles signing, encryption, and credential management — the private key **never** leaves the server process.

## Install

**From source:**

```bash
cargo install --path .
```

**Or build locally:**

```bash
cargo build --release
# Binary at ./target/release/oaid-mcp-server
```

## Quick start

### 1. Encrypt your credential (recommended)

```bash
oaid-mcp-server encrypt agent.credential.json
# Creates agent.credential.enc (chmod 600)
# You can now delete the plaintext .json file
```

### 2. Configure with Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "oaid": {
      "command": "/path/to/oaid-mcp-server",
      "env": {
        "OAID_CREDENTIAL_FILE": "/path/to/agent.credential.enc",
        "OAID_PASSPHRASE": "your-passphrase"
      }
    }
  }
}
```

If `OAID_PASSPHRASE` is omitted, the server prompts interactively at startup (works in terminal, not with Claude Desktop).

## Environment variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OAID_CREDENTIAL_FILE` | Path to credential file (`.json` or `.enc`) | *required* |
| `OAID_PASSPHRASE` | Passphrase for encrypted credentials | prompts interactively |
| `OAID_CREDENTIAL_DIR` | Directory to scan for agent credentials | `~/.oaid/` |

## CLI usage

```
oaid-mcp-server                    # Run MCP server (stdio)
oaid-mcp-server encrypt <file>     # Encrypt a credential file
oaid-mcp-server help               # Show help
```

## MCP tools

The server exposes 8 tools via MCP:

| Tool | Description |
|------|-------------|
| `oaid_whoami` | Return this agent's DID and public info (no private key) |
| `oaid_sign_request` | Sign an HTTP request, returns auth headers to attach |
| `oaid_check_credit` | Check the credit score of any agent by DID |
| `oaid_lookup_agent` | Look up agent info by DID (safe public fields only) |
| `oaid_send_message` | Send a signed message to another agent |
| `oaid_get_messages` | Get messages addressed to this agent |
| `oaid_send_encrypted_message` | Send an end-to-end encrypted message (NaCl box) |
| `oaid_list_agents` | List credential files in ~/.oaid/ directory |

## Security model

- **Private key isolation**: The Ed25519 signing key is loaded into the server process memory and never exposed through any MCP tool response.
- **Encrypted credentials**: AES-256-GCM encryption with Argon2id key derivation. Encrypted files are stored with `chmod 600`.
- **No key in responses**: Tool responses only contain DIDs, public info, signed headers, and operation results. The `oaid_list_agents` tool reads only the `did` and `agent_address` fields from credential files.
- **Signed requests**: All authenticated registry requests use Ed25519 signatures with timestamp and nonce to prevent replay attacks.
- **End-to-end encryption**: `oaid_send_encrypted_message` uses X25519-XSalsa20-Poly1305 (NaCl box) so only the recipient can decrypt.

## License

Apache-2.0
