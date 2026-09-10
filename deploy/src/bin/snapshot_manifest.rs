//! Offline snapshot manifest and initial-proof export.
use anyhow::{bail, Context, Result};
use kasmelt_harness::snapshot::{demo_source, Snapshot};
use std::io::{Read, Write};

const MAX_INPUT: u64 = 1_048_576;

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.as_slice() == ["example"] {
        println!("{}", serde_json::to_string_pretty(&demo_source())?);
        return Ok(());
    }
    if !matches!(
        args.first().map(String::as_str),
        Some("build" | "summary" | "proof")
    ) {
        bail!("usage: snapshot_manifest example | build <snapshot.json> | summary <snapshot.json> | proof <snapshot.json> <index>");
    }
    let path = args.get(1).context("snapshot JSON path is required")?;
    let mut text = String::new();
    std::fs::File::open(path)?
        .take(MAX_INPUT + 1)
        .read_to_string(&mut text)?;
    if text.len() as u64 > MAX_INPUT {
        bail!("snapshot exceeds 1 MiB");
    }
    let snapshot = Snapshot::parse_json(&text)?;
    match args[0].as_str() {
        "build" => {
            // The exact manifest commitment excludes a trailing newline.
            std::io::stdout()
                .lock()
                .write_all(snapshot.manifest_json.as_bytes())?;
        }
        "summary" => println!("{}", serde_json::to_string_pretty(&snapshot.summary())?),
        "proof" => {
            let index = args
                .get(2)
                .context("holder index is required")?
                .parse::<usize>()?;
            let vector = snapshot.merkle_vector(index)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "scope": "initial snapshot root; refresh proofs after accepted claims",
                    "holder": snapshot.holders.get(index).context("unknown holder")?,
                    "proof": vector
                }))?
            );
        }
        _ => unreachable!(),
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}
