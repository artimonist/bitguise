mod compress;
mod encrypt;
mod search;
mod transform;
mod translate;

use encrypt::EncryptCommand;
use translate::TranslateCommand;

pub trait Execute {
    fn execute(&self) -> anyhow::Result<()>;
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

    /// Search mnemonic words from a given article.
    // Search(SearchCommand),

    /// Transform a mnemonic to another.
    // Transform(TransformCommand),

    /// Encrypt mnemonic 12 to another mnemonic
    Encrypt(EncryptCommand),
}
