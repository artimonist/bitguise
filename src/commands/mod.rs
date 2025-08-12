mod encrypt;
mod translate;

use encrypt::EncryptCommand;
use translate::TranslateCommand;

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
    /// Encrypt mnemonic or private key.
    Encrypt(EncryptCommand<true>),
    /// Decrypt mnemonic or private key.
    Decrypt(EncryptCommand<false>),
}

pub trait Execute {
    fn execute(&self) -> anyhow::Result<()>;
}
