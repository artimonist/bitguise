use crate::commands::Execute;
use disguise::{Mnemonic, Transform};

#[derive(clap::Parser, Debug)]
pub struct TransformCommand {
    /// The mnemonic or wif to transform.
    #[clap(value_name = "MNEMONIC|PRIVATE KEY")]
    pub source: Source,
}

#[derive(Debug, Clone)]
pub enum Source {
    Mnemonic(Mnemonic),
    Wif(String),
}

impl std::str::FromStr for Source {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.parse::<Mnemonic>() {
            Ok(x) => Ok(Source::Mnemonic(x)),
            Err(_) => Ok(Source::Wif(s.to_string())),
        }
    }
}

impl Execute for TransformCommand {
    fn execute(&self) -> anyhow::Result<()> {
        match &self.source {
            Source::Mnemonic(mnemonic) => {
                let wif = mnemonic.to_string().mnemonic_to_wif()?;
                println!("{wif}");
            }
            Source::Wif(wif) => {
                let original = wif.mnemonic_from_wif()?;
                println!("{original}");
            }
        }
        Ok(())
    }
}
