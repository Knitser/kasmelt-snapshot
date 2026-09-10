//! Compile SilverScript with positional constructor arguments and emit script hex.

use debugger_session::args::parse_ctor_args;
use silverscript_lang::ast::parse_contract_ast;
use silverscript_lang::compiler::{CompileOptions, compile_contract};

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .ok_or("usage: snapshot-silverc <contract.sil> [constructor arguments...]")?;
    let source = std::fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?;
    let contract = parse_contract_ast(&source).map_err(|e| format!("parse: {e:?}"))?;
    let constructor = parse_ctor_args(&contract, &args.collect::<Vec<_>>())?;
    let compiled = compile_contract(&source, &constructor, CompileOptions::default())
        .map_err(|e| format!("compile: {e:?}"))?;
    println!("{}", hex::encode(compiled.script));
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
