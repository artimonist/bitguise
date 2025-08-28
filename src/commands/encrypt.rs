use crate::utils::inquire_password;
use disguise::MnemonicEncryption;

#[derive(clap::Parser, Debug)]
pub struct EncryptCommand {
    /// Mnemonic to encrypt or decrypt.
    #[clap(value_name = "MNEMONIC")]
    pub key: String,

    /// The multiple passwords to encrypt or decrypt.
    #[clap(long, value_parser, num_args = 1.., value_delimiter = ' ')]
    pub path: Vec<String>,

    /// The password to encrypt or decrypt.
    #[clap(hide = true, long = "password")]
    pub password: Option<String>,

    #[clap(skip)]
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
        if !self.path.is_empty() {
            // path encrypt or decrypt
            return Ok(());
        }

        let password = match self.password {
            Some(ref s) => s.clone(),
            None => inquire_password(false)?,
        };

        if self.encrypt {
            let encrypted = self.key.mnemonic_encrypt(&password)?;
            println!("{encrypted}");
        } else {
            let original = self.key.mnemonic_decrypt(&password)?;
            println!("{original}")
        }
        Ok(())
    }
}
