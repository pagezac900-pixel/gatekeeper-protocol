//! Gatekeeper CLI
//!
//! Usage:
//!   gatekeeper propose "<description>" <payload_file>
//!   gatekeeper verify  <token.json>    <payload_file>
//!   gatekeeper audit   [--session-key <keyfile>]

use gatekeeper_sdk::{AuthToken, GatekeeperSession, Outcome, iso_from_secs};
use std::path::Path;
use std::process;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        usage();
        process::exit(2);
    }

    match args[1].as_str() {
        "propose" => cmd_propose(&args[1..]),
        "verify"  => cmd_verify(&args[1..]),
        "audit"   => cmd_audit(&args[1..]),
        other => {
            eprintln!("gatekeeper: unknown command '{other}'");
            usage();
            process::exit(2);
        }
    }
}

// ── propose ───────────────────────────────────────────────────────────────────

fn cmd_propose(args: &[String]) {
    // propose "<description>" <payload_file> [--key <keyfile>]
    if args.len() < 3 {
        eprintln!("Usage: gatekeeper propose \"<description>\" <payload_file> [--key <keyfile>]");
        process::exit(2);
    }

    let description = &args[1];
    let payload_path = Path::new(&args[2]);

    // Optional persistent key
    let mut session = resolve_session(args);

    let payload = match std::fs::read(payload_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("gatekeeper: cannot read payload file '{}': {e}", payload_path.display());
            process::exit(2);
        }
    };

    let action = session.propose(description, &payload);
    let token = session.request_authorization(&action);

    match token {
        Some(t) => {
            // Write token JSON to stdout so callers can capture it.
            let json = serde_json::to_string_pretty(&t).expect("serialise token");
            println!("{json}");
            process::exit(0);
        }
        None => {
            eprintln!("gatekeeper: action was denied or cancelled.");
            process::exit(1);
        }
    }
}

// ── verify ────────────────────────────────────────────────────────────────────

fn cmd_verify(args: &[String]) {
    // verify <token.json> <payload_file>
    if args.len() < 3 {
        eprintln!("Usage: gatekeeper verify <token.json> <payload_file>");
        process::exit(2);
    }

    let token_path = Path::new(&args[1]);
    let payload_path = Path::new(&args[2]);

    let token_json = match std::fs::read_to_string(token_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("gatekeeper: cannot read token file: {e}");
            process::exit(2);
        }
    };
    let token: AuthToken = match serde_json::from_str(&token_json) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("gatekeeper: invalid token JSON: {e}");
            process::exit(2);
        }
    };

    let payload = match std::fs::read(payload_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("gatekeeper: cannot read payload file: {e}");
            process::exit(2);
        }
    };

    // Verification does not need the session's own private key — the token
    // carries the approver's public key.  We use a temporary session purely
    // to call verify().
    let session = GatekeeperSession::new();
    if session.verify_no_ttl(&token, &payload) {
        let ts = iso_from_secs(token.approved_at);
        let pk = hex::encode(token.approver_pubkey);
        println!("VERIFIED: approved by {pk} at {ts}");
        process::exit(0);
    } else {
        println!("INVALID");
        process::exit(1);
    }
}

// ── audit ─────────────────────────────────────────────────────────────────────

fn cmd_audit(args: &[String]) {
    let session = resolve_session(args);
    let trail = session.audit_trail();
    if trail.is_empty() {
        eprintln!("gatekeeper: audit log is empty for this session.");
        return;
    }
    for (i, entry) in trail.iter().enumerate() {
        let outcome_str = match &entry.outcome {
            Outcome::Approved(t) => format!("APPROVED  (token action_id={})", hex::encode(t.action_id)),
            Outcome::Denied      => "DENIED".to_owned(),
            Outcome::Cancelled   => "CANCELLED".to_owned(),
        };
        println!(
            "[{i:04}] {} | {} | {}",
            iso_from_secs(entry.recorded_at),
            outcome_str,
            entry.action.description,
        );
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn resolve_session(args: &[String]) -> GatekeeperSession {
    // Look for --key <path> anywhere in the slice
    for i in 0..args.len().saturating_sub(1) {
        if args[i] == "--key" {
            let keyfile = Path::new(&args[i + 1]);
            return GatekeeperSession::from_keyfile(keyfile)
                .unwrap_or_else(|e| {
                    eprintln!("gatekeeper: cannot load keyfile: {e}");
                    process::exit(2);
                });
        }
    }
    GatekeeperSession::new()
}

fn usage() {
    eprintln!("Gatekeeper Protocol SDK v{}", env!("CARGO_PKG_VERSION"));
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("  gatekeeper propose \"<description>\" <payload_file> [--key <keyfile>]");
    eprintln!("  gatekeeper verify  <token.json> <payload_file>");
    eprintln!("  gatekeeper audit   [--key <keyfile>]");
    eprintln!();
    eprintln!("COMMANDS:");
    eprintln!("  propose   Present an AI-proposed action for human review.");
    eprintln!("            Reads payload file, blocks on stdin for AUTHORIZE/DENY.");
    eprintln!("            On AUTHORIZE: prints AuthToken JSON to stdout, exits 0.");
    eprintln!("            On DENY/cancel: exits 1.");
    eprintln!();
    eprintln!("  verify    Verify an AuthToken against the original payload.");
    eprintln!("            Prints 'VERIFIED: ...' or 'INVALID', exits 0 or 1.");
    eprintln!();
    eprintln!("  audit     Print all authorisation decisions for this session.");
}
