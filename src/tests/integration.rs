// Integration tests for the Gatekeeper Protocol SDK.
// This file is include!()-d inside `mod integration` in lib.rs,
// so all crate-level items are in scope via `use crate::*`.

use crate::{AuthToken, GatekeeperSession, Outcome, TOKEN_TTL_SECS};
use std::time::{SystemTime, UNIX_EPOCH};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn make_approved_token(
    session: &GatekeeperSession,
    payload: &[u8],
) -> AuthToken {
    let action = session.propose("test action", payload);
    session.sign_token_for_test(&action, now())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[test]
fn test_propose_produces_correct_hash() {
    let session = GatekeeperSession::new();
    let payload = b"echo 'hello world' >> /tmp/output.txt";
    let action = session.propose("Append greeting to temp file", payload);
    let expected: [u8; 32] = *blake3::hash(payload).as_bytes();
    assert_eq!(action.payload_hash, expected, "payload hash must be blake3 of payload");
    assert_eq!(action.description, "Append greeting to temp file");
}

#[test]
fn test_authorize_returns_valid_token() {
    let session = GatekeeperSession::new();
    let payload = b"terraform apply -auto-approve";
    let token = make_approved_token(&session, payload);
    assert!(
        session.verify_no_ttl(&token, payload),
        "fresh token must verify against original payload"
    );
}

#[test]
fn test_deny_logs_denied_entry() {
    let mut session = GatekeeperSession::new();
    let payload = b"rm -rf /";
    let action = session.propose("Delete everything", payload);
    session.inject_deny_for_test(&action);

    let trail = session.audit_trail();
    assert_eq!(trail.len(), 1);
    assert!(matches!(trail[0].outcome, Outcome::Denied));
}

#[test]
fn test_verify_correct_payload_passes() {
    let session = GatekeeperSession::new();
    let payload = b"git push origin main";
    let token = make_approved_token(&session, payload);
    assert!(session.verify_no_ttl(&token, payload));
}

#[test]
fn test_verify_tampered_payload_fails() {
    let session = GatekeeperSession::new();
    let payload = b"git push origin main";
    let token = make_approved_token(&session, payload);
    let tampered = b"git push origin main --force";
    assert!(
        !session.verify_no_ttl(&token, tampered),
        "tampered payload must not verify"
    );
}

#[test]
fn test_verify_tampered_signature_fails() {
    let session = GatekeeperSession::new();
    let payload = b"deploy to staging";
    let mut token = make_approved_token(&session, payload);
    token.signature[0] ^= 0xFF;
    assert!(!session.verify_no_ttl(&token, payload), "corrupted signature must not verify");
}

#[test]
fn test_verify_expired_token_fails() {
    let session = GatekeeperSession::new();
    let payload = b"send email blast";
    let action = session.propose("Marketing email", payload);
    let stale_time = now().saturating_sub(TOKEN_TTL_SECS + 1);
    let token = session.sign_token_for_test(&action, stale_time);
    // verify() enforces TTL; verify_no_ttl() does not
    assert!(!session.verify(&token, payload), "expired token must not pass verify()");
    assert!(session.verify_no_ttl(&token, payload), "expired token must still pass verify_no_ttl()");
}

#[test]
fn test_audit_log_records_approved_entry() {
    let mut session = GatekeeperSession::new();
    let payload = b"kubectl rollout restart deployment/api";
    let action = session.propose("Restart API pods", payload);
    let token = session.sign_token_for_test(&action, now());
    session.inject_approved_for_test(&action, token);

    let trail = session.audit_trail();
    assert_eq!(trail.len(), 1);
    assert!(matches!(&trail[0].outcome, Outcome::Approved(_)));
    assert_eq!(trail[0].action.description, "Restart API pods");
}

#[test]
fn test_pubkey_hex_is_stable_within_session() {
    let session = GatekeeperSession::new();
    assert_eq!(session.pubkey_hex(), session.pubkey_hex());
    assert_eq!(session.pubkey_hex().len(), 64);
}

#[test]
fn test_export_audit_json_creates_file() {
    let mut session = GatekeeperSession::new();
    let payload = b"vacuum database";
    let action = session.propose("DB vacuum", payload);
    let token = session.sign_token_for_test(&action, now());
    session.inject_approved_for_test(&action, token);

    let dir = tempfile::tempdir().unwrap();
    let out_path = dir.path().join("audit.json");
    session.export_audit_json(&out_path).expect("export should succeed");

    let contents = std::fs::read_to_string(&out_path).unwrap();
    let val: serde_json::Value = serde_json::from_str(&contents).unwrap();
    assert!(val.get("entries").is_some());
    assert!(val.get("signer_pubkey").is_some());
    assert!(val.get("signature").is_some());
}
