use clap::Parser;
use subs::app::{App, CertCmd, Cli, Commands};

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    let args = Cli::parse();
    let app = App::new(&args.c)?;
    match args.cmd {
        Commands::Status => app.cmd_status()?,
        Commands::Add(a) => app.cmd_add(a)?,
        Commands::Commit(a) => app.cmd_commit(a)?,
        Commands::Prove(a) => app.cmd_prove(a)?,
        Commands::Compress(a) => app.cmd_compress_snark(a)?,
        Commands::Cert(a) => {
            match a {
                CertCmd::Issue(a) => app.cmd_cert_issue(a)?,
                CertCmd::Verify(a) => app.cmd_cert_verify(a)?,
            }
        }
        Commands::Request(a) => app.cmd_create(a)?,
    }
    Ok(())
}
