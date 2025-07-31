mod bip39;
mod commands;
mod utils;

pub use bip39::{Language, Mnemonic};
// pub use utils::{inquire_password, select_language};

use crate::commands::{Cli, Commands, Execute};
use clap::Parser;

fn main() {
    let args = Cli::parse();
    match args.command {
        Commands::Translate(cmd) => cmd.execute(),
        // Commands::Search(cmd) => cmd.execute(),
        // Commands::Transform(cmd) => cmd.execute(),
        Commands::Encrypt(cmd) => cmd.execute(),
    }
    .unwrap_or_else(|e| eprintln!("Error: {e}"))
}
