use std::{fs::OpenOptions, io::Write, os::unix::fs::OpenOptionsExt, path::PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use rand::RngCore;

#[derive(Parser)]
#[command(about = "Create a test-only VERZ Link lab secret without printing it")]
struct Args {
    #[arg(long)]
    output: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let mut secret = [0_u8; 32];
    rand::rng().fill_bytes(&mut secret);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&args.output)
        .with_context(|| format!("create {}", args.output.display()))?;
    writeln!(file, "{}", hex::encode(secret))?;
    println!("Created a 0600 lab secret at {}", args.output.display());
    Ok(())
}
