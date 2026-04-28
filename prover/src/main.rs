//! subs-prover, ZK prover for subs.
//!
//! Generates STARK proofs for step and fold operations, and SNARK compression.
//! Designed to run on GPU-enabled machines separate from the main subs operator.
//!
//! # Usage
//!
//! Run as an HTTP server:
//! ```bash
//! subs-prover --server --server-port 8888
//! ```
//!
//! One-shot proving from CLI:
//! ```bash
//! subs-prover prove -i request.json -o receipt.bin
//! subs-prover compress -i compress_input.json -o snark.bin
//! ```

use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use subs_prover::Prover;
use subs_types::{CompressInput, ProvingRequest};

#[derive(Parser)]
#[command(
    name = "subs-prover",
    about = "ZK prover for subs - generates STARK/SNARK proofs",
    version
)]
struct Cli {
    /// Run as an HTTP server that accepts proving requests
    #[arg(long)]
    server: bool,

    /// Server port (for --server mode)
    #[arg(long, default_value = "8888")]
    server_port: u16,

    #[command(subcommand)]
    cmd: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Prove a ProvingRequest (Step or Fold)
    Prove {
        /// Input file (JSON ProvingRequest). If not provided, reads from stdin.
        #[arg(short, long)]
        input: Option<PathBuf>,
        /// Output file for receipt. If not provided, writes to stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Compress a STARK proof to SNARK (Groth16)
    Compress {
        /// Input file (JSON CompressInput). If not provided, reads from stdin.
        #[arg(short, long)]
        input: Option<PathBuf>,
        /// Output file for receipt. If not provided, writes to stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Benchmark: estimate proving cost for inserting handles into a tree
    Bench {
        /// Number of existing handles in the tree
        #[arg(long, default_value = "10000")]
        existing: usize,
        /// Number of new handles to insert
        #[arg(long, default_value = "100")]
        insert: usize,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.server {
        subs_prover::server::run_server(cli.server_port).await?;
        return Ok(());
    }

    match cli.cmd {
        Some(Commands::Prove { input, output }) => {
            let input_data = read_input(input)?;
            let request: ProvingRequest = serde_json::from_slice(&input_data)?;
            let receipt = prove(&request)?;
            write_output(output, &receipt)?;
        }
        Some(Commands::Compress { input, output }) => {
            let input_data = read_input(input)?;
            let compress_input: CompressInput = serde_json::from_slice(&input_data)?;
            let receipt = compress(&compress_input)?;
            write_output(output, &receipt)?;
        }
        Some(Commands::Bench { existing, insert }) => {
            run_bench(existing, insert)?;
        }
        None => {
            eprintln!("Usage: subs-prover --server    (run as HTTP server)");
            eprintln!("       subs-prover prove       (prove single request)");
            eprintln!("       subs-prover compress    (compress to SNARK)");
            eprintln!("       subs-prover bench       (benchmark proving cost)");
            eprintln!();
            eprintln!("Run with --help for more options.");
            std::process::exit(1);
        }
    }

    Ok(())
}

fn read_input(path: Option<PathBuf>) -> Result<Vec<u8>> {
    match path {
        Some(p) => Ok(fs::read(&p)?),
        None => {
            let mut buf = Vec::new();
            io::stdin().read_to_end(&mut buf)?;
            Ok(buf)
        }
    }
}

fn write_output(path: Option<PathBuf>, receipt: &[u8]) -> Result<()> {
    match path {
        Some(p) => {
            fs::write(&p, receipt)?;
            eprintln!("Receipt written to {}", p.display());
        }
        None => {
            io::stdout().write_all(receipt)?;
        }
    }
    Ok(())
}

fn prove(request: &ProvingRequest) -> Result<Vec<u8>> {
    let idx = request.idx();
    eprintln!("[#{}] Starting proof...", idx);
    let prover = Prover::new();
    let result = prover.prove(request);
    if result.is_ok() {
        eprintln!("[#{}] Proof complete.", idx);
    }
    result
}

fn compress(input: &CompressInput) -> Result<Vec<u8>> {
    eprintln!("Starting SNARK compression...");
    let prover = Prover::new();
    let result = prover.compress(input);
    if result.is_ok() {
        eprintln!("SNARK compression complete.");
    }
    result
}

fn run_bench(existing: usize, insert: usize) -> Result<()> {
    eprintln!("Building tree with {} existing handles, {} inserts...", existing, insert);
    let start = std::time::Instant::now();
    let request = subs_prover::build_bench_request(existing, insert)?;
    eprintln!("Request built in {:.2}s", start.elapsed().as_secs_f64());

    eprintln!("\nCalibrating...");
    let prover = Prover::new();
    let calibration = match prover.calibrate() {
        Ok(info) => {
            eprintln!(
                "Calibration: {:.2}s per segment at po2={}\n",
                info.seconds_per_segment, info.calibration_po2
            );
            Some(info)
        }
        Err(e) => {
            eprintln!("Calibration failed: {}\n", e);
            None
        }
    };

    eprintln!("Estimating proof for {} handles inserted into tree of {}...", insert, existing);
    let estimate = prover.estimate(&request, calibration.as_ref())?;

    eprintln!("\n=== Estimate ===");
    eprintln!("Total user cycles:    {}", estimate.total_cycles);
    eprintln!("Total proving cycles: {} (padded)", estimate.total_proving_cycles);
    eprintln!("Segments:             {}", estimate.segments);
    for (i, seg) in estimate.segment_details.iter().enumerate() {
        let time_str = seg.estimated_seconds
            .map(|s| format!("{:.2}s", s))
            .unwrap_or_else(|| "n/a".into());
        eprintln!(
            "  Segment {}: {} user cycles, po2={}, est. {}",
            i, seg.cycles, seg.po2, time_str
        );
    }
    if let Some(total) = estimate.estimated_seconds {
        eprintln!("\nEstimated total proving time: {:.1}s", total);
    }

    Ok(())
}
