use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// Demo implementation of the Universal Vault Migration in Rust.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    #[command(subcommand)]
    pub operation: Operation,
}

#[derive(Debug, Subcommand, Clone)]
pub enum Operation {
    Import(Import),
    Export(Export),
    List,
}

#[derive(Debug, Clone, Args)]
pub struct Import {
    pub path: PathBuf,
}

#[derive(Debug, Clone, Args)]
pub struct Export {
    pub path: PathBuf,
}
