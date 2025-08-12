use crate::utils::inquire_password;
use disguise::{BIP38, MnemonicEncryption};

#[derive(clap::Parser, Debug)]
pub struct EncryptCommand<const E: bool> {
    /// Mnemonic or private key to encrypt or decrypt.
    pub key: String,

    // /// The target language for the mnemonic.
    // #[clap(hide = true, long = "target")]
    // pub language: Option<Language>,
    /// The password to encrypt the mnemonic.
    #[clap(hide = true, long = "password")]
    pub password: Option<String>,
}

impl<const E: bool> crate::Execute for EncryptCommand<E> {
    fn execute(&self) -> anyhow::Result<()> {
        // let language = match self.language {
        //     Some(ref lang) => *lang,
        //     None => select_language(&Language::all())?,
        // };
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
            let result = match E {
                true => self.key.mnemonic_encrypt(&password, 24)?,
                false => self.key.mnemonic_decrypt(&password)?,
            };
            println!("{result}");
        }
        Ok(())
    }
}
