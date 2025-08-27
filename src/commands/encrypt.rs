use crate::utils::inquire_password;
use clap::builder::{PossibleValuesParser, TypedValueParser};
use disguise::{Mnemonic, MnemonicEncryption};

#[derive(clap::Parser, Debug)]
pub struct EncryptCommand {
    /// Mnemonic to encrypt or decrypt.
    pub mnemonic: String,

    /// Desired mnemonic word count.
    #[clap(value_name = "WORD COUNT", value_parser = PossibleValuesParser::new(["12", "15", "18", "21", "24"])
        .map(|s| s.parse::<u8>().unwrap()))]
    pub count: Option<u8>,

    /// The password to encrypt or decrypt the mnemonic.
    #[clap(hide = true, long = "password")]
    pub password: Option<String>,

    encrypt: bool,
}

impl EncryptCommand {
    pub fn encrypt(mut self) -> Self {
        self.encrypt = true;
        self
    }

    pub fn decrypt(mut self) -> Self {
        self.encrypt = false;
        self
    }
}

impl crate::Execute for EncryptCommand {
    fn execute(&self) -> anyhow::Result<()> {
        let password = match self.password {
            Some(ref pass) => pass.clone(),
            None => inquire_password(false)?,
        };

        let count = self.count.unwrap_or(0) as usize;
        let result = match self.encrypt {
            true => self.mnemonic.mnemonic_encrypt(&password)?,
            false => {
                let word_count = self.mnemonic.split_whitespace().count();
                if count != 0 && Mnemonic::valid_size(word_count) {
                    let mnemonic = format!("{}; {count}", self.mnemonic);
                    mnemonic.mnemonic_decrypt(&password)?
                } else {
                    self.mnemonic.mnemonic_decrypt(&password)?
                }
            }
        };
        println!("{result}");
        Ok(())
    }
}
