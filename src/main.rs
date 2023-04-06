use clap::Parser;

mod cli;
mod crypto;
mod schema;

fn main() {
    let args = cli::Cli::parse();
    println!(
        "{:?}ing from {}",
        args.operation,
        args.operation.path().unwrap().display()
    );
}
