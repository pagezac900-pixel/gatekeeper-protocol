//! Gatekeeper Protocol SDK
//!
//! Cryptographically-enforced human authorisation for AI systems.
//!
//! # Flow
//!
//! ```text
//! AI proposes action
//!   → GatekeeperSession::propose(description, payload)  → PendingAction
//!   → GatekeeperSession::request_authorization(action)  → Option<AuthToken>
//!        (blocks on stdin; returns Some only if human types "AUTHORIZE")
//!   → on Some: action may execute
//!   → GatekeeperSession::verify(token, payload)         → bool
//! ```
//!
//! Cryptographic primitives mirror lumina-hive/dna:
//!   Ed25519 (ed25519-dalek 2), BLAKE3, OsRng nonces.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

// ── Time helper ───────────────────────────────────────────────────────────────

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs()
}

// ── Token validity window ─────────────────────────────────────────────────────

/// An AuthToken is valid for this many seconds after `approved_at`.
pub const TOKEN_TTL_SECS: u64 = 300;

// ── Core types ────────────────────────────────────────────────────────────────

/// A proposed AI action awaiting human authorisation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingAction {
    /// 16-byte random action ID (hex-encoded in JSON).
    #[serde(with = "hex_16")]
    pub id: [u8; 16],
    /// Human-readable description of what the AI intends to do.
    pub description: String,
    /// BLAKE3 hash of the raw payload bytes (hex-encoded in JSON).
    #[serde(with = "hex_32")]
    pub payload_hash: [u8; 32],
    /// Unix timestamp (seconds) when this action was proposed.
    pub proposed_at: u64,
}

/// Proof that a specific human approved a specific payload at a specific time.
///
/// An `AuthToken` is cryptographically bound to:
/// - the action ID (`action_id`)
/// - the payload hash (`payload_hash`)
/// - the exact approval time (`approved_at`)
/// - the approver's Ed25519 public key (`approver_pubkey`)
///
/// The `signature` covers all four fields; tampering with any one of them
/// invalidates the token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthToken {
    /// Matches `PendingAction::id`.
    #[serde(with = "hex_16")]
    pub action_id: [u8; 16],
    /// BLAKE3 hash of the payload that was authorised.
    #[serde(with = "hex_32")]
    pub payload_hash: [u8; 32],
    /// Unix timestamp (seconds) when AUTHORIZE was typed.
    pub approved_at: u64,
    /// Ed25519 verifying key of the session that issued this token.
    #[serde(with = "hex_32")]
    pub approver_pubkey: [u8; 32],
    /// Ed25519 signature over `action_id || payload_hash || approved_at(8 bytes BE) || approver_pubkey`.
    #[serde(with = "hex_64")]
    pub signature: [u8; 64],
}

/// Outcome of a human-authorisation request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "outcome", content = "token")]
pub enum Outcome {
    Approved(AuthToken),
    Denied,
    Cancelled,
}

/// One record in the append-only audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub action: PendingAction,
    pub outcome: Outcome,
    pub recorded_at: u64,
}

// ── GatekeeperSession ─────────────────────────────────────────────────────────

/// A session that can propose, authorise, verify, and audit AI actions.
///
/// Each session has an Ed25519 signing keypair.  Use `new()` for an ephemeral
/// key or `from_keyfile()` for a persistent identity that survives restarts.
pub struct GatekeeperSession {
    keypair: SigningKey,
    audit_log: Vec<AuditEntry>,
}

impl GatekeeperSession {
    // ── Constructors ──────────────────────────────────────────────────────────

    /// Create a session with a fresh ephemeral Ed25519 keypair.
    pub fn new() -> Self {
        let keypair = SigningKey::generate(&mut OsRng);
        Self { keypair, audit_log: Vec::new() }
    }

    /// Load or create a persistent Ed25519 keypair stored at `path`.
    ///
    /// The file contains the 32-byte raw seed (little-endian scalar) in hex.
    /// If the file does not exist it is created with a newly-generated key.
    pub fn from_keyfile(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let keypair = if path.exists() {
            let hex_str = std::fs::read_to_string(path)?.trim().to_owned();
            let bytes = hex::decode(&hex_str)?;
            if bytes.len() != 32 {
                return Err("keyfile must contain exactly 32 hex-decoded bytes".into());
            }
            let seed: [u8; 32] = bytes.try_into().unwrap();
            SigningKey::from_bytes(&seed)
        } else {
            let key = SigningKey::generate(&mut OsRng);
            let hex_str = hex::encode(key.to_bytes());
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, &hex_str)?;
            key
        };
        Ok(Self { keypair, audit_log: Vec::new() })
    }

    // ── Core API ──────────────────────────────────────────────────────────────

    /// Build a `PendingAction` from a description and raw payload bytes.
    ///
    /// Does **not** block or write to the audit log; just constructs the struct.
    pub fn propose(&self, description: &str, payload: &[u8]) -> PendingAction {
        let mut id = [0u8; 16];
        OsRng.fill_bytes(&mut id);

        let hash = blake3::hash(payload);
        let payload_hash: [u8; 32] = *hash.as_bytes();

        PendingAction {
            id,
            description: description.to_owned(),
            payload_hash,
            proposed_at: now_secs(),
        }
    }

    /// Present the action to the human operator on **stdout/stdin** and wait.
    ///
    /// Returns `Some(AuthToken)` only if the operator types exactly `AUTHORIZE`.
    /// Any other input (including `DENY`, blank line, or EOF) returns `None`.
    /// Either outcome is recorded in the audit log.
    pub fn request_authorization(&mut self, action: &PendingAction) -> Option<AuthToken> {
        // Print the authorisation prompt to stderr so stdout stays clean for
        // JSON piping when running as a CLI tool.
        let hash_hex = hex::encode(action.payload_hash);
        eprintln!();
        eprintln!("┌─── GATEKEEPER AUTHORIZATION REQUEST ──────────────────────────────────────┐");
        eprintln!("│ Action ID   : {}", hex::encode(action.id));
        eprintln!("│ Description : {}", action.description);
        eprintln!("│ Payload hash: {}…", &hash_hex[..16]);
        eprintln!("│              (blake3, full: {})", hash_hex);
        eprintln!("│ Proposed at : {} UTC", iso_from_secs(action.proposed_at));
        eprintln!("└────────────────────────────────────────────────────────────────────────────┘");
        eprint!("  Type AUTHORIZE to approve, anything else to deny: ");
        let _ = io::stderr().flush();

        let stdin = io::stdin();
        let line = stdin.lock().lines().next();

        let response = match line {
            Some(Ok(l)) => l.trim().to_owned(),
            _ => String::new(),
        };

        let recorded_at = now_secs();

        if response == "AUTHORIZE" {
            let token = self.sign_token(action, recorded_at);
            self.audit_log.push(AuditEntry {
                action: action.clone(),
                outcome: Outcome::Approved(token.clone()),
                recorded_at,
            });
            eprintln!("  [GATEKEEPER] Approved — token issued.");
            Some(token)
        } else {
            let outcome = if response.is_empty() { Outcome::Cancelled } else { Outcome::Denied };
            self.audit_log.push(AuditEntry {
                action: action.clone(),
                outcome,
                recorded_at,
            });
            eprintln!("  [GATEKEEPER] Denied — action blocked.");
            None
        }
    }

    /// Verify an `AuthToken` against a payload.
    ///
    /// Checks:
    /// 1. The Ed25519 signature is valid for the token's stated fields.
    /// 2. The BLAKE3 hash of `payload` matches `token.payload_hash`.
    /// 3. The `approved_at` timestamp is within [`TOKEN_TTL_SECS`] of now.
    ///
    /// All three checks must pass.  Returns `false` on any failure.
    pub fn verify(&self, token: &AuthToken, payload: &[u8]) -> bool {
        // 1. Signature check
        let Ok(vk) = VerifyingKey::from_bytes(&token.approver_pubkey) else {
            return false;
        };
        let msg = token_signing_msg(token);
        let Ok(sig) = Signature::from_slice(&token.signature) else {
            return false;
        };
        if vk.verify(&msg, &sig).is_err() {
            return false;
        }

        // 2. Payload hash check
        let computed: [u8; 32] = *blake3::hash(payload).as_bytes();
        if computed != token.payload_hash {
            return false;
        }

        // 3. TTL check
        let now = now_secs();
        if now.saturating_sub(token.approved_at) > TOKEN_TTL_SECS {
            return false;
        }

        true
    }

    /// Verify a token without the TTL check (useful for historical audit replay).
    pub fn verify_no_ttl(&self, token: &AuthToken, payload: &[u8]) -> bool {
        let Ok(vk) = VerifyingKey::from_bytes(&token.approver_pubkey) else {
            return false;
        };
        let msg = token_signing_msg(token);
        let Ok(sig) = Signature::from_slice(&token.signature) else {
            return false;
        };
        if vk.verify(&msg, &sig).is_err() {
            return false;
        }
        let computed: [u8; 32] = *blake3::hash(payload).as_bytes();
        computed == token.payload_hash
    }

    // ── Audit ─────────────────────────────────────────────────────────────────

    /// Borrow the complete audit log for this session.
    pub fn audit_trail(&self) -> &[AuditEntry] {
        &self.audit_log
    }

    /// Serialise the audit log as a signed JSON object and write it to `path`.
    ///
    /// The JSON envelope has the shape:
    /// ```json
    /// { "entries": [...], "signer_pubkey": "<hex>", "signature": "<hex>" }
    /// ```
    /// The signature covers the UTF-8 bytes of the serialised `entries` array.
    pub fn export_audit_json(&self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let entries_json = serde_json::to_string_pretty(&self.audit_log)?;
        let sig: Signature = self.keypair.sign(entries_json.as_bytes());
        let envelope = serde_json::json!({
            "entries": &self.audit_log,
            "signer_pubkey": hex::encode(self.keypair.verifying_key().to_bytes()),
            "signature": hex::encode(sig.to_bytes()),
        });
        let out = serde_json::to_string_pretty(&envelope)?;
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        std::fs::write(path, out)?;
        Ok(())
    }

    /// Hex-encoded Ed25519 verifying key for this session.
    pub fn pubkey_hex(&self) -> String {
        hex::encode(self.keypair.verifying_key().to_bytes())
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    fn sign_token(&self, action: &PendingAction, approved_at: u64) -> AuthToken {
        let approver_pubkey = self.keypair.verifying_key().to_bytes();
        let mut token = AuthToken {
            action_id: action.id,
            payload_hash: action.payload_hash,
            approved_at,
            approver_pubkey,
            signature: [0u8; 64],
        };
        let msg = token_signing_msg(&token);
        let sig: Signature = self.keypair.sign(&msg);
        token.signature = sig.to_bytes();
        token
    }
}

impl Default for GatekeeperSession {
    fn default() -> Self {
        Self::new()
    }
}

// ── Token signing message ─────────────────────────────────────────────────────

/// Canonical byte string signed inside an AuthToken.
///
/// Layout: action_id(16) || payload_hash(32) || approved_at(8 BE) || approver_pubkey(32) = 88 bytes
fn token_signing_msg(token: &AuthToken) -> Vec<u8> {
    let mut msg = Vec::with_capacity(88);
    msg.extend_from_slice(&token.action_id);
    msg.extend_from_slice(&token.payload_hash);
    msg.extend_from_slice(&token.approved_at.to_be_bytes());
    msg.extend_from_slice(&token.approver_pubkey);
    msg
}

// ── ISO-8601 formatter ────────────────────────────────────────────────────────

/// Format a Unix timestamp as a minimal UTC ISO-8601 string (no external crate).
pub fn iso_from_secs(ts: u64) -> String {
    // Minimal implementation; no leap-second handling.
    let mut s = ts;
    let secs = s % 60; s /= 60;
    let mins = s % 60; s /= 60;
    let hours = s % 24; s /= 24;

    // Days since epoch → date
    let mut days = s as u32;
    let mut year = 1970u32;
    loop {
        let days_in_year = if is_leap(year) { 366 } else { 365 };
        if days < days_in_year { break; }
        days -= days_in_year;
        year += 1;
    }
    let months = if is_leap(year) {
        [31u32, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31u32, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month = 0usize;
    for (i, &m) in months.iter().enumerate() {
        if days < m { month = i + 1; break; }
        days -= m;
    }
    let day = days + 1;

    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{mins:02}:{secs:02}Z")
}

fn is_leap(y: u32) -> bool {
    (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
}

// ── Serde helpers for fixed-size byte arrays ──────────────────────────────────

mod hex_16 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8; 16], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 16], D::Error> {
        let h = String::deserialize(d)?;
        let b = hex::decode(&h).map_err(serde::de::Error::custom)?;
        b.try_into().map_err(|_| serde::de::Error::custom("expected 16 bytes"))
    }
}

mod hex_32 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let h = String::deserialize(d)?;
        let b = hex::decode(&h).map_err(serde::de::Error::custom)?;
        b.try_into().map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

mod hex_64 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let h = String::deserialize(d)?;
        let b = hex::decode(&h).map_err(serde::de::Error::custom)?;
        b.try_into().map_err(|_| serde::de::Error::custom("expected 64 bytes"))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn propose_creates_correct_hash() {
        let session = GatekeeperSession::new();
        let payload = b"deploy v1.2.3 to production";
        let action = session.propose("Deploy release", payload);
        let expected: [u8; 32] = *blake3::hash(payload).as_bytes();
        assert_eq!(action.payload_hash, expected);
        assert!(!action.description.is_empty());
        assert!(action.proposed_at > 0);
    }

    #[test]
    fn sign_token_is_verifiable() {
        let session = GatekeeperSession::new();
        let payload = b"some payload";
        let action = session.propose("Test action", payload);
        let approved_at = now_secs();
        let token = session.sign_token(&action, approved_at);
        assert!(session.verify_no_ttl(&token, payload));
    }

    #[test]
    fn verify_tampered_payload_fails() {
        let session = GatekeeperSession::new();
        let payload = b"original payload";
        let action = session.propose("Test", payload);
        let token = session.sign_token(&action, now_secs());
        assert!(!session.verify_no_ttl(&token, b"tampered payload"));
    }

    #[test]
    fn iso_from_secs_epoch() {
        assert_eq!(iso_from_secs(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn pubkey_hex_is_64_chars() {
        let s = GatekeeperSession::new();
        assert_eq!(s.pubkey_hex().len(), 64);
    }
}

// ── Test-only helpers (compiled only under `#[cfg(test)]`) ───────────────────

#[cfg(any(test, feature = "test-helpers"))]
impl GatekeeperSession {
    /// Sign a token at the given timestamp without stdin. For tests only.
    pub fn sign_token_for_test(&self, action: &PendingAction, approved_at: u64) -> AuthToken {
        self.sign_token(action, approved_at)
    }

    /// Inject a pre-built Approved entry into the audit log. For tests only.
    pub fn inject_approved_for_test(&mut self, action: &PendingAction, token: AuthToken) {
        self.audit_log.push(AuditEntry {
            action: action.clone(),
            outcome: Outcome::Approved(token),
            recorded_at: now_secs(),
        });
    }

    /// Inject a Denied entry into the audit log. For tests only.
    pub fn inject_deny_for_test(&mut self, action: &PendingAction) {
        self.audit_log.push(AuditEntry {
            action: action.clone(),
            outcome: Outcome::Denied,
            recorded_at: now_secs(),
        });
    }
}

// ── Integration tests (live in their own file) ────────────────────────────────

#[cfg(test)]
mod integration {
    // Re-export for use inside integration.rs via `use super::*`
    include!("tests/integration.rs");
}
