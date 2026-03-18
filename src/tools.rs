//! MCP tool implementations for Open Agent ID.
//!
//! All 8 tools are dispatched from here. The private key NEVER appears
//! in any tool response.

use std::sync::OnceLock;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use crypto_box::aead::{Aead, AeadCore, OsRng};
use crypto_box::{PublicKey as BoxPublicKey, SalsaBox, SecretKey as BoxSecretKey};
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::Signer;
use serde_json::{json, Value};
use sha2::{Digest, Sha512};

use crate::credential::{self, Credential};

// ---------------------------------------------------------------------------
// Global credential (loaded once at startup)
// ---------------------------------------------------------------------------

static CREDENTIAL: OnceLock<Credential> = OnceLock::new();

/// Initialize the global credential. Called once at startup.
pub fn init_credential(cred: Credential) {
    CREDENTIAL
        .set(cred)
        .unwrap_or_else(|_| panic!("credential already initialized"));
}

fn get_cred() -> Result<&'static Credential, String> {
    CREDENTIAL.get().ok_or_else(|| "credential not loaded".to_string())
}

// ---------------------------------------------------------------------------
// HTTP client
// ---------------------------------------------------------------------------

fn http_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("failed to build HTTP client")
    })
}

// ---------------------------------------------------------------------------
// Crypto helpers
// ---------------------------------------------------------------------------

/// Build auth headers for a signed HTTP request.
fn sign_payload(cred: &Credential) -> (String, String, String, String) {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_secs()
        .to_string();

    let nonce = hex::encode(rand::random::<[u8; 16]>());
    let payload = format!("{}\n{}\n{}", cred.did, timestamp, nonce);
    let signature = cred.signing_key.sign(payload.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    (cred.did.clone(), timestamp, nonce, sig_b64)
}

/// Build auth headers as a map.
fn auth_headers(cred: &Credential) -> Vec<(String, String)> {
    let (did, ts, nonce, sig) = sign_payload(cred);
    vec![
        ("X-Agent-DID".into(), did),
        ("X-Agent-Timestamp".into(), ts),
        ("X-Agent-Nonce".into(), nonce),
        ("X-Agent-Signature".into(), sig),
    ]
}

/// Signed GET to registry.
async fn registry_get(cred: &Credential, path: &str, signed: bool) -> Result<Value, String> {
    let url = format!("{}{}", cred.registry_url, path);
    let mut req = http_client().get(&url);
    if signed {
        for (k, v) in auth_headers(cred) {
            req = req.header(&k, &v);
        }
    }
    let resp = req.send().await.map_err(|e| format!("HTTP request failed: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("registry returned {status}: {body}"));
    }
    resp.json::<Value>()
        .await
        .map_err(|e| format!("failed to parse response: {e}"))
}

/// Signed POST to registry.
async fn registry_post(cred: &Credential, path: &str, payload: &Value) -> Result<Value, String> {
    let url = format!("{}{}", cred.registry_url, path);
    let body_str = serde_json::to_string(payload).unwrap_or_default();
    let headers = auth_headers(cred);

    let mut req = http_client()
        .post(&url)
        .header("Content-Type", "application/json")
        .body(body_str);
    for (k, v) in headers {
        req = req.header(&k, &v);
    }

    let resp = req.send().await.map_err(|e| format!("HTTP request failed: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("registry returned {status}: {body}"));
    }
    resp.json::<Value>()
        .await
        .map_err(|e| format!("failed to parse response: {e}"))
}

/// Convert an Ed25519 public key to X25519 for NaCl box encryption.
fn ed25519_to_x25519_public(ed25519_pub: &[u8; 32]) -> Result<[u8; 32], String> {
    let compressed = CompressedEdwardsY::from_slice(ed25519_pub)
        .map_err(|e| format!("invalid Ed25519 public key: {e}"))?;
    let edwards = compressed
        .decompress()
        .ok_or_else(|| "failed to decompress Ed25519 point".to_string())?;
    Ok(edwards.to_montgomery().to_bytes())
}

/// Convert an Ed25519 signing key to X25519 private key.
fn ed25519_to_x25519_private(signing_key: &ed25519_dalek::SigningKey) -> [u8; 32] {
    let hash = <Sha512 as Digest>::digest(signing_key.as_bytes());
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash[..32]);
    key[0] &= 248;
    key[31] &= 127;
    key[31] |= 64;
    key
}

/// Encrypt plaintext for a recipient using NaCl box.
fn encrypt_for(
    plaintext: &[u8],
    recipient_ed25519_pub: &[u8; 32],
    sender_signing_key: &ed25519_dalek::SigningKey,
) -> Result<Vec<u8>, String> {
    let sender_x25519 = ed25519_to_x25519_private(sender_signing_key);
    let recipient_x25519 = ed25519_to_x25519_public(recipient_ed25519_pub)?;

    let sender_secret = BoxSecretKey::from(sender_x25519);
    let recipient_public = BoxPublicKey::from(recipient_x25519);

    let salsa_box = SalsaBox::new(&recipient_public, &sender_secret);
    let nonce = SalsaBox::generate_nonce(&mut OsRng);
    let encrypted = salsa_box
        .encrypt(&nonce, plaintext)
        .map_err(|e| format!("encryption failed: {e}"))?;

    let mut result = Vec::with_capacity(24 + encrypted.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&encrypted);
    Ok(result)
}

// ---------------------------------------------------------------------------
// Tool dispatch
// ---------------------------------------------------------------------------

/// Dispatch an MCP tool call by name.
pub async fn dispatch(tool_name: &str, arguments: &Value) -> Result<Value, String> {
    match tool_name {
        "oaid_whoami" => tool_whoami().await,
        "oaid_sign_request" => tool_sign_request(arguments).await,
        "oaid_check_credit" => tool_check_credit(arguments).await,
        "oaid_lookup_agent" => tool_lookup_agent(arguments).await,
        "oaid_send_message" => tool_send_message(arguments).await,
        "oaid_get_messages" => tool_get_messages().await,
        "oaid_send_encrypted_message" => tool_send_encrypted_message(arguments).await,
        "oaid_list_agents" => tool_list_agents().await,
        _ => Err(format!("unknown tool: {tool_name}")),
    }
}

// ---------------------------------------------------------------------------
// Tool implementations
// ---------------------------------------------------------------------------

/// 1. oaid_whoami — Returns DID and public info. NO private key.
async fn tool_whoami() -> Result<Value, String> {
    let cred = get_cred()?;
    Ok(json!({
        "did": cred.did,
        "agent_address": cred.agent_address,
        "chain": cred.chain,
        "registry_url": cred.registry_url,
    }))
}

/// 2. oaid_sign_request — Build auth headers for a signed HTTP request.
async fn tool_sign_request(args: &Value) -> Result<Value, String> {
    let _method = args
        .get("method")
        .and_then(|v| v.as_str())
        .ok_or("missing required parameter: method")?;
    let _url = args
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or("missing required parameter: url")?;

    let cred = get_cred()?;
    let (did, timestamp, nonce, sig) = sign_payload(cred);

    Ok(json!({
        "headers": {
            "X-Agent-DID": did,
            "X-Agent-Timestamp": timestamp,
            "X-Agent-Nonce": nonce,
            "X-Agent-Signature": sig,
        }
    }))
}

/// 3. oaid_check_credit — GET {registry}/v1/credit/{did}
async fn tool_check_credit(args: &Value) -> Result<Value, String> {
    let did = args
        .get("did")
        .and_then(|v| v.as_str())
        .ok_or("missing required parameter: did")?;

    let cred = get_cred()?;
    registry_get(cred, &format!("/v1/credit/{did}"), false).await
}

/// 4. oaid_lookup_agent — GET {registry}/v1/agents/{did}, filter to safe fields.
async fn tool_lookup_agent(args: &Value) -> Result<Value, String> {
    let did = args
        .get("did")
        .and_then(|v| v.as_str())
        .ok_or("missing required parameter: did")?;

    let cred = get_cred()?;
    let data = registry_get(cred, &format!("/v1/agents/{did}"), false).await?;

    // Filter to safe public fields only
    let safe_fields = [
        "did",
        "chain",
        "chain_status",
        "capabilities",
        "credit_score",
        "created_at",
    ];

    let mut result = serde_json::Map::new();
    if let Some(obj) = data.as_object() {
        for field in &safe_fields {
            if let Some(val) = obj.get(*field) {
                result.insert(field.to_string(), val.clone());
            }
        }
    }

    Ok(Value::Object(result))
}

/// 5. oaid_send_message — Sign + POST {registry}/v1/messages
async fn tool_send_message(args: &Value) -> Result<Value, String> {
    let to_did = args
        .get("to_did")
        .and_then(|v| v.as_str())
        .ok_or("missing required parameter: to_did")?;
    let body = args
        .get("body")
        .ok_or("missing required parameter: body")?;
    let msg_type = args
        .get("msg_type")
        .and_then(|v| v.as_str())
        .unwrap_or("default");

    let cred = get_cred()?;
    let payload = json!({
        "to": to_did,
        "msg_type": msg_type,
        "body": body,
    });

    registry_post(cred, "/v1/messages", &payload).await
}

/// 6. oaid_get_messages — Sign + GET {registry}/v1/messages?to={own_did}
async fn tool_get_messages() -> Result<Value, String> {
    let cred = get_cred()?;
    registry_get(cred, &format!("/v1/messages?to={}", cred.did), true).await
}

/// 7. oaid_send_encrypted_message — Lookup recipient key, encrypt, send.
async fn tool_send_encrypted_message(args: &Value) -> Result<Value, String> {
    let to_did = args
        .get("to_did")
        .and_then(|v| v.as_str())
        .ok_or("missing required parameter: to_did")?;
    let plaintext = args
        .get("plaintext")
        .and_then(|v| v.as_str())
        .ok_or("missing required parameter: plaintext")?;

    let cred = get_cred()?;

    // Look up recipient to get their public key
    let agent_info = registry_get(cred, &format!("/v1/agents/{to_did}"), false).await?;
    let recipient_pk_b64 = agent_info
        .get("public_key")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("recipient {to_did} has no public key in the registry"))?;

    let recipient_pk_bytes = URL_SAFE_NO_PAD
        .decode(recipient_pk_b64)
        .map_err(|e| format!("failed to decode recipient public key: {e}"))?;
    let recipient_pk: [u8; 32] = recipient_pk_bytes
        .try_into()
        .map_err(|_| "recipient public key must be 32 bytes".to_string())?;

    let ciphertext = encrypt_for(plaintext.as_bytes(), &recipient_pk, &cred.signing_key)?;
    let ct_b64 = URL_SAFE_NO_PAD.encode(&ciphertext);

    let payload = json!({
        "to": to_did,
        "msg_type": "encrypted",
        "body": {
            "ciphertext": ct_b64,
            "enc": "x25519-xsalsa20-poly1305",
            "sender_public_key": cred.public_key_b64,
        },
    });

    let mut result = registry_post(cred, "/v1/messages", &payload).await?;
    if let Some(obj) = result.as_object_mut() {
        obj.insert("encrypted".into(), json!(true));
    }
    Ok(result)
}

/// 8. oaid_list_agents — Scan ~/.oaid/ for credential files, list DIDs.
async fn tool_list_agents() -> Result<Value, String> {
    let cred_dir = std::env::var("OAID_CREDENTIAL_DIR").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        format!("{home}/.oaid")
    });

    let dir = std::path::Path::new(&cred_dir);
    if !dir.is_dir() {
        return Ok(json!({ "agents": [], "directory": cred_dir }));
    }

    let mut agents = Vec::new();

    let entries = std::fs::read_dir(dir)
        .map_err(|e| format!("failed to read directory {cred_dir}: {e}"))?;

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        let file_name = entry.file_name().to_string_lossy().to_string();
        if !file_name.ends_with(".credential.json")
            && !file_name.ends_with(".credential.enc")
        {
            continue;
        }

        let path = entry.path().to_string_lossy().to_string();
        let name = file_name
            .trim_end_matches(".credential.json")
            .trim_end_matches(".credential.enc")
            .to_string();

        match credential::read_did_only(&path) {
            Ok((did, agent_address)) => {
                agents.push(json!({
                    "name": name,
                    "did": did,
                    "agent_address": agent_address,
                    "file": file_name,
                    "encrypted": file_name.ends_with(".enc"),
                }));
            }
            Err(_) => {
                // Encrypted files or unreadable — still list them
                agents.push(json!({
                    "name": name,
                    "file": file_name,
                    "encrypted": file_name.ends_with(".enc"),
                    "did": null,
                }));
            }
        }
    }

    Ok(json!({
        "agents": agents,
        "directory": cred_dir,
    }))
}
