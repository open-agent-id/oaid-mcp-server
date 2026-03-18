//! Load, encrypt, and decrypt Open Agent ID credential files.
//!
//! Supports both plaintext JSON and encrypted (AES-256-GCM + Argon2id) formats.
//! The encrypted format starts with `OAID_ENC\n` followed by base64-encoded salt,
//! nonce, and ciphertext on separate lines.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, KeyInit};
use argon2::Argon2;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use ed25519_dalek::SigningKey;
use serde::Deserialize;

/// Parsed agent credential. Private key material is kept in memory only.
pub struct Credential {
    pub did: String,
    pub agent_address: String,
    pub public_key_b64: String,
    pub chain: String,
    pub registry_url: String,
    pub signing_key: SigningKey, // NEVER exposed via MCP tools
}

/// Raw JSON structure of a credential file.
#[derive(Deserialize)]
struct RawCredential {
    did: String,
    agent_address: String,
    public_key: String,
    private_key: String,
    chain: String,
    registry_url: String,
}

/// Derive a 32-byte AES key from a passphrase using Argon2id.
fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| format!("Argon2 key derivation failed: {e}"))?;
    Ok(key)
}

/// Decode a base64url (no-padding) string, tolerating missing padding.
fn b64url_decode(s: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| format!("base64url decode failed: {e}"))
}

/// Parse a raw credential JSON object into a `Credential`.
fn parse_raw(raw: RawCredential) -> Result<Credential, String> {
    let sk_bytes = b64url_decode(&raw.private_key)?;
    let seed: [u8; 32] = if sk_bytes.len() == 64 {
        sk_bytes[..32]
            .try_into()
            .map_err(|_| "invalid private key bytes".to_string())?
    } else if sk_bytes.len() == 32 {
        sk_bytes
            .try_into()
            .map_err(|_| "invalid private key bytes".to_string())?
    } else {
        return Err(format!(
            "invalid private key length: {} (expected 32 or 64)",
            sk_bytes.len()
        ));
    };

    let signing_key = SigningKey::from_bytes(&seed);

    Ok(Credential {
        did: raw.did,
        agent_address: raw.agent_address,
        public_key_b64: raw.public_key,
        chain: raw.chain,
        registry_url: raw.registry_url.trim_end_matches('/').to_string(),
        signing_key,
    })
}

/// Load a credential file, auto-detecting encrypted vs plaintext.
pub fn load(path: &str) -> Result<Credential, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("failed to read credential file {path}: {e}"))?;

    let content = content.trim();

    if content.starts_with("OAID_ENC") {
        let passphrase = std::env::var("OAID_PASSPHRASE").unwrap_or_default();
        let passphrase = if passphrase.is_empty() {
            rpassword::prompt_password("Enter passphrase to decrypt credential: ")
                .map_err(|e| format!("failed to read passphrase: {e}"))?
        } else {
            passphrase
        };
        let raw_json = decrypt_content(content, &passphrase)?;
        let raw: RawCredential = serde_json::from_str(&raw_json)
            .map_err(|e| format!("invalid credential JSON: {e}"))?;
        parse_raw(raw)
    } else {
        let raw: RawCredential = serde_json::from_str(content)
            .map_err(|e| format!("invalid credential JSON: {e}"))?;
        parse_raw(raw)
    }
}

/// Decrypt the content of an encrypted credential file. Returns the plaintext JSON string.
fn decrypt_content(content: &str, passphrase: &str) -> Result<String, String> {
    let lines: Vec<&str> = content.lines().collect();
    if lines.len() < 4 || lines[0] != "OAID_ENC" {
        return Err("not an encrypted credential file (missing OAID_ENC header)".into());
    }

    let salt = STANDARD
        .decode(lines[1])
        .map_err(|e| format!("invalid salt: {e}"))?;
    let nonce_bytes = STANDARD
        .decode(lines[2])
        .map_err(|e| format!("invalid nonce: {e}"))?;
    let ciphertext = STANDARD
        .decode(lines[3])
        .map_err(|e| format!("invalid ciphertext: {e}"))?;

    let key = derive_key(passphrase, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| format!("failed to create cipher: {e}"))?;
    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| "wrong passphrase or corrupted file".to_string())?;

    String::from_utf8(plaintext).map_err(|e| format!("decrypted content is not valid UTF-8: {e}"))
}

/// Encrypt a plaintext credential file. Prompts for passphrase (double entry).
/// Saves the encrypted file with `.enc` extension and chmod 600.
pub fn encrypt_file(input_path: &str) -> Result<String, String> {
    let path = Path::new(input_path);
    if !path.is_file() {
        return Err(format!("file not found: {input_path}"));
    }

    let plaintext = fs::read(path)
        .map_err(|e| format!("failed to read file: {e}"))?;

    // Validate it's valid credential JSON
    let _: RawCredential = serde_json::from_slice(&plaintext)
        .map_err(|e| format!("invalid credential JSON: {e}"))?;

    let passphrase =
        rpassword::prompt_password("Enter passphrase to encrypt credential: ")
            .map_err(|e| format!("failed to read passphrase: {e}"))?;
    let confirm =
        rpassword::prompt_password("Confirm passphrase: ")
            .map_err(|e| format!("failed to read passphrase: {e}"))?;

    if passphrase != confirm {
        return Err("passphrases do not match".into());
    }

    // Generate salt and derive key
    use rand::RngCore;
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);

    let key = derive_key(&passphrase, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| format!("failed to create cipher: {e}"))?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_ref())
        .map_err(|e| format!("encryption failed: {e}"))?;

    // Build output: OAID_ENC\n{salt}\n{nonce}\n{ciphertext}\n
    let output = format!(
        "OAID_ENC\n{}\n{}\n{}\n",
        STANDARD.encode(&salt),
        STANDARD.encode(&nonce),
        STANDARD.encode(&ciphertext),
    );

    let out_path = path.with_extension("enc");
    fs::write(&out_path, &output)
        .map_err(|e| format!("failed to write encrypted file: {e}"))?;

    // chmod 600
    let metadata = fs::metadata(&out_path)
        .map_err(|e| format!("failed to read file metadata: {e}"))?;
    let mut perms = metadata.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(&out_path, perms)
        .map_err(|e| format!("failed to set file permissions: {e}"))?;

    Ok(out_path.to_string_lossy().to_string())
}

/// Read only the DID and agent_address from a credential file (for listing).
/// Never loads the private key into a SigningKey.
pub fn read_did_only(path: &str) -> Result<(String, String), String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("failed to read {path}: {e}"))?;
    let content = content.trim();

    // For encrypted files, we can't read without passphrase — skip
    if content.starts_with("OAID_ENC") {
        return Err("encrypted file (cannot read DID without passphrase)".into());
    }

    #[derive(Deserialize)]
    struct Partial {
        did: String,
        agent_address: String,
    }

    let partial: Partial = serde_json::from_str(content)
        .map_err(|e| format!("invalid JSON: {e}"))?;

    Ok((partial.did, partial.agent_address))
}
