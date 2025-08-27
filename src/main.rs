mod bip39;
mod commands;
mod utils;

use crate::commands::{Cli, Commands, Execute};
pub use bip39::{Language, Mnemonic};
use clap::Parser;

fn main() {
    let args = Cli::parse();
    match args.command {
        Commands::Translate(cmd) => cmd.execute(),
        Commands::Encrypt(cmd) => cmd.encrypt().execute(),
        Commands::Decrypt(cmd) => cmd.decrypt().execute(),
        Commands::Transform(cmd) => cmd.execute(),
    }
    .unwrap_or_else(|e| eprintln!("Error: {e}"))
}
