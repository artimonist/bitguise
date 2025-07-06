mod commands;

use crate::commands::{RetrieveCommand, TransformCommand, TranslateCommand};
use clap::Parser;

fn main() {
    let args = Cli::parse();
    println!("{args:?}");
}

/// Disguise mnemonics and wallets in a simple way.
#[derive(clap::Parser, Debug)]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(clap::Subcommand, Debug)]
pub enum Commands {
    /// Translate a mnemonic to a different language.
    Translate(TranslateCommand),

    /// Retrieve a mnemonic from a given article.
    Retrieve(RetrieveCommand),

    /// Transform a mnemonic to another.
    Transform(TransformCommand),
}
