use crate::utils::inquire_password;
use clap::builder::{PossibleValuesParser, TypedValueParser};
use disguise::{BIP38, MnemonicEncryption};

#[derive(clap::Parser, Debug)]
pub struct EncryptCommand<const E: bool> {
    /// Mnemonic or private key to encrypt or decrypt.
    pub key: String,

    /// Desired mnemonic word count.
    #[clap(value_name = "WORD COUNT", value_parser = PossibleValuesParser::new(["12", "15", "18", "21", "24"])
        .map(|s| s.parse::<u8>().unwrap()))]
    pub count: Option<u8>,

    /// The password to encrypt the mnemonic.
    #[clap(hide = true, long = "password")]
    pub password: Option<String>,
}

impl<const E: bool> crate::Execute for EncryptCommand<E> {
    fn execute(&self) -> anyhow::Result<()> {
        let password = match self.password {
            Some(ref pass) => pass.clone(),
            None => inquire_password(false)?,
        };

        if self.key.starts_with(['K', 'L', '5']) && self.key.len() == 53 {
            // private key
            let result = match E {
                true => self.key.bip38_encrypt(&password)?,
                false => self.key.bip38_decrypt(&password)?,
            };
            println!("{result}");
        } else {
            // mnemonic
            let count = self.count.unwrap_or(0) as usize;
            let result = match E {
                true => self.key.mnemonic_encrypt(&password, count)?,
                false => self.key.mnemonic_decrypt(&password)?,
            };
            println!("{result}");
        }
        Ok(())
    }
}
