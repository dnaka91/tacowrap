use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueHint};

#[derive(Parser)]
#[command(about, author, version)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Test the overall file encryption performance.
    Bench(BenchArgs),
    /// Mount an encrypted directory as plaintext folder.
    Mount(MountArgs),
}

#[derive(Args)]
pub struct BenchArgs {
    /// Encrypted directory.
    #[arg(value_hint = ValueHint::DirPath)]
    pub dir: PathBuf,
}

#[derive(Args)]
pub struct MountArgs {
    /// Run in the foreground instead of forking to a background process.
    #[arg(long)]
    pub foreground: bool,
    /// Encrypted directory.
    #[arg(value_hint = ValueHint::DirPath)]
    pub source: PathBuf,
    /// Plaintext directory to mount.
    #[arg(value_hint = ValueHint::DirPath)]
    pub target: PathBuf,
}

impl Cli {
    pub fn parse() -> Self {
        <Self as Parser>::parse()
    }
}
