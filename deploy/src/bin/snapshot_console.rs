//! Local, offline UI for the snapshot-claim proof of concept.
//!
//! This process binds only to loopback, holds no external wallet key, reaches
//! no RPC, and never constructs a submission path. Deterministic fixture keys
//! sign the local setup/fee inputs. POST routes require a non-simple
//! custom header so an unrelated web page cannot drive the local state with a
//! cross-origin form submission.
//!
//!     cargo run --manifest-path deploy/Cargo.toml --bin snapshot_console

use kasmelt_harness::snapshot::{demo_source, Snapshot, SnapshotLab, ABI_STATUS, SPEC_PIN};
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{Arc, Mutex},
    time::Duration,
};

const PAGE: &str = include_str!("../../web/snapshot.html");
const MAX_BODY: usize = 1_048_576;
const MAX_HEADER_BYTES: usize = 32_768;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archive_is_complete_and_explicitly_historical() {
        let record = archived_tn10_receipts();
        assert_eq!(record["complete"], true);
        assert_eq!(record["archived"], true);
        assert_eq!(record["confirmed"], 5);
        assert_eq!(record["recorded_on"], "2026-08-26");
        assert!(record.get("pins").is_none());
        assert!(record.get("rpc_url").is_none());
    }

    #[test]
    fn malformed_or_incomplete_receipts_cannot_report_complete() {
        let mut record: Value =
            serde_json::from_str(include_str!("../../../evidence/tn10-2026-08-26.json")).unwrap();
        record["claim"] = record["scope"].clone();
        record["network"] = json!("mainnet");
        assert_eq!(receipt_projection(&record)["available"], false);
        record["network"] = json!("testnet-10");
        record["receipts"][0]["transaction_id"] = json!("invalid");
        assert_eq!(receipt_projection(&record)["complete"], false);
        record["receipts"][0] = record["receipts"][1].clone();
        assert_eq!(receipt_projection(&record)["complete"], false);
    }
}

fn receipts_unavailable(reason: &str) -> Value {
    json!({
            "available": false,
            "complete": false,
            "confirmed": 0,
            "reason": reason,
            "receipts": [],
    })
}

fn archived_tn10_receipts() -> Value {
    let mut record: Value =
        serde_json::from_str(include_str!("../../../evidence/tn10-2026-08-26.json"))
            .expect("bundled evidence JSON");
    record["claim"] = record["scope"].clone();
    record["archived"] = json!(true);
    receipt_projection(&record)
}

fn live_tn10_receipts() -> Value {
    let Ok(home) = std::env::var("HOME") else {
        return archived_tn10_receipts();
    };
    let path = format!("{home}/.kasmelt-snapshot/tn10-snapshot-state.json");
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return archived_tn10_receipts();
        }
        Err(_) => return receipts_unavailable("The local TN10 ledger could not be read"),
    };
    let Ok(state) = serde_json::from_slice::<Value>(&bytes) else {
        return receipts_unavailable("TN10 receipt ledger is malformed");
    };
    receipt_projection(&state)
}

// A receipt projection is a record, not a fresh network verification.
fn receipt_projection(state: &Value) -> Value {
    if state.get("network").and_then(Value::as_str) != Some("testnet-10")
        || !state
            .get("claim")
            .and_then(Value::as_str)
            .is_some_and(|claim| claim.starts_with("SYNTHETIC MECHANICS TEST ONLY"))
    {
        return receipts_unavailable("TN10 receipt ledger has the wrong network or proof scope");
    }
    let receipts: Vec<Value> = state
        .get("receipts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|receipt| {
            let stage = receipt.get("stage")?.as_u64()?;
            let txid = receipt.get("transaction_id")?.as_str()?;
            if !(1..=5).contains(&stage)
                || txid.len() != 64
                || !txid.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                return None;
            }
            Some(json!({
                "stage": stage,
                "name": receipt.get("name").and_then(Value::as_str).unwrap_or("TN10 stage"),
                "transaction_id": txid,
                "accepting_daa": receipt.get("accepting_daa").and_then(Value::as_u64),
                "settled_virtual_daa": receipt.get("settled_virtual_daa")
                    .or_else(|| receipt.get("observed_virtual_daa")).and_then(Value::as_u64),
                "explorer": format!("https://explorer-tn10.kaspa.org/txs/{txid}"),
                "kascov": format!("https://kascov.io/data/testnet-10/tx/{txid}"),
            }))
        })
        .collect();
    let complete = receipts.len() == 5
        && (1..=5).all(|stage| {
            receipts
                .iter()
                .any(|receipt| receipt.get("stage").and_then(Value::as_u64) == Some(stage))
        });
    json!({
        "available": true,
        "complete": complete,
        "confirmed": receipts.len(),
        "archived": state.get("archived").and_then(Value::as_bool).unwrap_or(false),
        "recorded_on": state.get("recorded_on").and_then(Value::as_str),
        "scope": state.get("claim").and_then(Value::as_str),
        "manifest_commitment": state.get("manifest_commitment").and_then(Value::as_str),
        "initial_root": state.get("initial_root").and_then(Value::as_str),
        "current_root": state.get("current_root").and_then(Value::as_str),
        "reserve_amount": state.get("reserve_amount").and_then(Value::as_str),
        "token_id": state.get("token_id").and_then(Value::as_str),
        "controller_id": state.get("controller_id").and_then(Value::as_str),
        "receipts": receipts,
    })
}

#[derive(Clone, Serialize)]
struct Event {
    kind: String,
    title: String,
    detail: String,
    root_before: Option<String>,
    root_after: Option<String>,
    script_units: Option<u64>,
}

struct App {
    lab: SnapshotLab,
    events: Vec<Event>,
}

impl App {
    fn demo() -> Result<Self, String> {
        let snapshot = Snapshot::from_source(demo_source()).map_err(|e| e.to_string())?;
        let lab = SnapshotLab::new(snapshot).map_err(|e| e.to_string())?;
        let setup_units: u64 = [
            &lab.setup.token_genesis,
            &lab.setup.controller_genesis,
            &lab.setup.reserve_handoff,
        ]
        .iter()
        .flat_map(|stage| stage.input_script_units.iter())
        .sum();
        let event = Event {
            kind: "commit".to_string(),
            title: "Local genesis and reserve handoff accepted".to_string(),
            detail: format!(
                "Canonicalized {} holder leaves, then executed signed token genesis, controller genesis, and the full-supply handoff. Every input passed and all three transactions are within TN10 block-mass limits. Pinned {}.",
                lab.snapshot.holders.len(),
                SPEC_PIN
            ),
            root_before: None,
            root_after: Some(hex::encode(lab.current_root())),
            script_units: Some(setup_units),
        };
        Ok(Self {
            lab,
            events: vec![event],
        })
    }

    fn replace_snapshot(&mut self, body: &str) -> Result<(), String> {
        let snapshot = Snapshot::parse_json(body).map_err(|e| e.to_string())?;
        let lab = SnapshotLab::new(snapshot).map_err(|e| e.to_string())?;
        let setup_units: u64 = [
            &lab.setup.token_genesis,
            &lab.setup.controller_genesis,
            &lab.setup.reserve_handoff,
        ]
        .iter()
        .flat_map(|stage| stage.input_script_units.iter())
        .sum();
        let event = Event {
            kind: "commit".to_string(),
            title: "Snapshot and local setup rebuilt".to_string(),
            detail: format!(
                "Committed {} canonical leaves and {} base units, then engine-checked both genesis transactions and the signed reserve handoff.",
                lab.snapshot.holders.len(), lab.snapshot.total
            ),
            root_before: None,
            root_after: Some(hex::encode(lab.current_root())),
            script_units: Some(setup_units),
        };
        self.lab = lab;
        self.events = vec![event];
        Ok(())
    }

    fn claim(&mut self, index: usize) -> Result<(), String> {
        let holder = self
            .lab
            .snapshot
            .holders
            .get(index)
            .cloned()
            .ok_or_else(|| "unknown holder index".to_string())?;
        let result = self.lab.claim(index).map_err(|e| e.to_string())?;
        self.events.insert(
            0,
            Event {
                kind: "claim".to_string(),
                title: format!("Leaf {index} claimed in the Kaspa engine"),
                detail: format!(
                    "{} base units were forced to {}. Transaction {} passed every input and TN10 compute/transient/storage mass limits (compute {}/{}); its {} sompi fee covers the lab estimate of {}.",
                    holder.amount,
                    holder.address,
                    &result.transaction_id[..16],
                    result.mass.compute,
                    result.mass.compute_limit,
                    result.mass.fee_sompi,
                    result.mass.lab_fee_estimate_sompi
                ),
                root_before: Some(result.root_before),
                root_after: Some(result.root_after),
                script_units: Some(result.script_units),
            },
        );
        Ok(())
    }

    fn view(&self) -> Value {
        let holders: Vec<_> = self
            .lab
            .snapshot
            .holders
            .iter()
            .map(|holder| {
                let scheme = match holder.owner_scheme {
                    0x00 => "p2pk-schnorr/v1 (0x00)",
                    0x03 => "p2sh/v1 (0x03)",
                    _ => "unsupported",
                };
                json!({
                    "index": holder.index.to_string(),
                    "address": holder.address,
                    "amount": holder.amount.to_string(),
                    "owner_scheme": scheme,
                    "status": if holder.claimed { "claimed" } else { "claimable" },
                })
            })
            .collect();
        json!({
            "mode": "LOCAL ENGINE · NOTHING BROADCAST",
            "spec_pin": SPEC_PIN,
            "abi_status": ABI_STATUS,
            "network": self.lab.snapshot.source.network,
            "ticker": self.lab.snapshot.source.ticker,
            "source_json": self.lab.source_json(),
            "manifest_json": self.lab.snapshot.manifest_json,
            "token_id": hex::encode(self.lab.token_id),
            "controller_id": hex::encode(self.lab.controller_id),
            "setup": self.lab.setup,
            "manifest_commitment": hex::encode(self.lab.snapshot.manifest_commitment),
            "initial_root": hex::encode(self.lab.snapshot.initial_root),
            "current_root": hex::encode(self.lab.current_root()),
            "total": self.lab.snapshot.total.to_string(),
            "remaining": self.lab.reserve_amount.to_string(),
            "claimed_count": self.lab.claimed_count().to_string(),
            "holder_count": self.lab.snapshot.holders.len().to_string(),
            "holders": holders,
            "events": self.events,
            "tn10": live_tn10_receipts(),
            "guarantees": [
                "The holder list is canonicalized into deterministic owner tuples, amounts, and a Merkle root.",
                "Deterministic fixture transactions execute token genesis, controller genesis, and a signed full-supply reserve handoff before claims begin.",
                "Each click runs controller, token-reserve, and fee inputs through the real Kaspa TxScriptEngine, checks TN10 compute/transient/storage mass, and covers the conservative kascov-lab fee estimate.",
                "A claim forces the exact committed amount and owner, retires that leaf, and conserves token supply.",
                "Stale and duplicate proofs fail after the singleton root advances; critical cell KAS values are pinned.",
                "The immutable manifest commitment is embedded in token genesis, so changing it changes the token covenant ID."
            ],
            "limits": [
                "The KRC-20 balances and MuHash are supplied evidence. A Kaspa covenant cannot inspect historical KRC indexer state.",
                "This is offline construction: deterministic fixture keys sign local transactions, but no external wallet, node RPC, mempool, DAG consensus, or broadcast is involved.",
                "KCC-20 is still Draft; the local SilverScript compiler does not yet emit its final KCC-1 dispatch ABI.",
                "Legacy KRC-20 remains valid after the snapshot. This creates a claimable fork; social consensus decides which side has value.",
                "One evolving root serializes claims. Concurrent users must refresh their proof after another claim lands."
            ]
        })
    }
}

#[derive(Default)]
struct Request {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

fn read_request(stream: &TcpStream) -> Result<Request, String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("read timeout: {e}"))?;
    // The hard byte cap lives on the reader itself: read_line grows its buffer
    // until a newline arrives, so a newline-free stream must hit this limit
    // instead of ballooning memory on the single-threaded server.
    let mut reader = BufReader::new(stream.try_clone().map_err(|e| e.to_string())?)
        .take(MAX_HEADER_BYTES as u64);
    let mut request_line = String::new();
    reader
        .read_line(&mut request_line)
        .map_err(|e| e.to_string())?;
    if !request_line.ends_with('\n') && reader.limit() == 0 {
        return Err("headers too large".to_string());
    }
    if request_line.len() > 4_096 {
        return Err("request line too large".to_string());
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let raw_path = parts.next().unwrap_or("");
    let path = raw_path.split('?').next().unwrap_or("").to_string();
    if !matches!(method.as_str(), "GET" | "POST") || !path.starts_with('/') {
        return Err("malformed request".to_string());
    }

    let mut headers = BTreeMap::new();
    let mut header_bytes = request_line.len();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).map_err(|e| e.to_string())?;
        if !line.ends_with('\n') && reader.limit() == 0 {
            return Err("headers too large".to_string());
        }
        header_bytes += line.len();
        if header_bytes > MAX_HEADER_BYTES {
            return Err("headers too large".to_string());
        }
        if line == "\r\n" || line == "\n" || line.is_empty() {
            break;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| "malformed header".to_string())?;
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
    }
    let content_length = headers
        .get("content-length")
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|_| "invalid content-length".to_string())
        })
        .transpose()?
        .unwrap_or(0);
    if content_length > MAX_BODY {
        return Err("request body exceeds 1 MiB".to_string());
    }
    let mut body = vec![0u8; content_length];
    reader.set_limit(content_length as u64);
    reader.read_exact(&mut body).map_err(|e| e.to_string())?;
    Ok(Request {
        method,
        path,
        headers,
        body,
    })
}

fn response(
    mut stream: TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\n\
         Referrer-Policy: no-referrer\r\nCross-Origin-Resource-Policy: same-origin\r\n\
         Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

fn json_response(stream: TcpStream, status: &str, value: Value) -> std::io::Result<()> {
    response(
        stream,
        status,
        "application/json; charset=utf-8",
        value.to_string().as_bytes(),
    )
}

fn post_is_local(request: &Request, port: u16) -> bool {
    if request.headers.get("x-kasmelt-lab").map(String::as_str) != Some("1") {
        return false;
    }
    match request.headers.get("origin") {
        None => true,
        Some(origin) => {
            origin == &format!("http://127.0.0.1:{port}")
                || origin == &format!("http://localhost:{port}")
                // A public deployment names its own origin explicitly; anything
                // else stays rejected, so the CSRF posture is unchanged.
                || std::env::var("KASMELT_PUBLIC_ORIGIN")
                    .is_ok_and(|allowed| allowed.split(',').any(|a| a.trim() == origin))
        }
    }
}

fn handle(stream: TcpStream, app: &Arc<Mutex<App>>, port: u16) -> std::io::Result<()> {
    let request = match read_request(&stream) {
        Ok(request) => request,
        Err(message) => {
            return json_response(stream, "400 Bad Request", json!({ "error": message }));
        }
    };
    if request.method == "POST" && !post_is_local(&request, port) {
        return json_response(
            stream,
            "403 Forbidden",
            json!({ "error": "local mutation header/origin check failed" }),
        );
    }

    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/") => response(
            stream,
            "200 OK",
            "text/html; charset=utf-8",
            PAGE.as_bytes(),
        ),
        ("GET", "/api/state") => {
            let app = app
                .lock()
                .map_err(|_| std::io::Error::other("state lock poisoned"))?;
            json_response(stream, "200 OK", app.view())
        }
        ("POST", "/api/snapshot") => {
            let body = match std::str::from_utf8(&request.body) {
                Ok(body) => body,
                Err(_) => {
                    return json_response(
                        stream,
                        "400 Bad Request",
                        json!({ "error": "snapshot body must be UTF-8 JSON" }),
                    )
                }
            };
            let mut app = app
                .lock()
                .map_err(|_| std::io::Error::other("state lock poisoned"))?;
            match app.replace_snapshot(body) {
                Ok(()) => json_response(stream, "200 OK", json!({ "ok": true })),
                Err(error) => json_response(
                    stream,
                    "422 Unprocessable Content",
                    json!({ "error": error }),
                ),
            }
        }
        ("POST", "/api/reset") => {
            let reset = App::demo();
            match reset {
                Ok(reset) => {
                    *app.lock()
                        .map_err(|_| std::io::Error::other("state lock poisoned"))? = reset;
                    json_response(stream, "200 OK", json!({ "ok": true }))
                }
                Err(error) => json_response(
                    stream,
                    "500 Internal Server Error",
                    json!({ "error": error }),
                ),
            }
        }
        ("POST", path) if path.starts_with("/api/claim/") => {
            let raw = path.trim_start_matches("/api/claim/");
            let index = match raw.parse::<usize>() {
                Ok(index) if index.to_string() == raw => index,
                _ => {
                    return json_response(
                        stream,
                        "400 Bad Request",
                        json!({ "error": "claim index must be canonical unsigned decimal" }),
                    )
                }
            };
            let mut app = app
                .lock()
                .map_err(|_| std::io::Error::other("state lock poisoned"))?;
            match app.claim(index) {
                Ok(()) => json_response(stream, "200 OK", json!({ "ok": true })),
                Err(error) => json_response(stream, "409 Conflict", json!({ "error": error })),
            }
        }
        _ => json_response(stream, "404 Not Found", json!({ "error": "not found" })),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let port = args
        .iter()
        .position(|arg| arg == "--port")
        .and_then(|at| args.get(at + 1))
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(8793);
    let app = match App::demo() {
        Ok(app) => Arc::new(Mutex::new(app)),
        Err(error) => {
            eprintln!("snapshot lab startup failed: {error}");
            std::process::exit(1);
        }
    };
    let listener = TcpListener::bind(("127.0.0.1", port)).unwrap_or_else(|error| {
        eprintln!("cannot bind 127.0.0.1:{port}: {error}");
        std::process::exit(1);
    });
    println!("Snapshot Claim Lab  http://127.0.0.1:{port}");
    println!("Offline real-engine construction. Fixture keys only; no RPC, external key custody, or broadcast path.");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let _ = handle(stream, &app, port);
            }
            Err(error) => eprintln!("connection error: {error}"),
        }
    }
}
