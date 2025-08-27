mod encrypt;
mod transform;
mod translate;

use encrypt::EncryptCommand;
use transform::TransformCommand;
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
    /// Encrypt mnemonic to another.
    Encrypt(EncryptCommand),
    /// Decrypt mnemonic.
    Decrypt(EncryptCommand),
    /// Transform mnemonic.
    Transform(TransformCommand),
}

pub trait Execute {
    fn execute(&self) -> anyhow::Result<()>;
}
