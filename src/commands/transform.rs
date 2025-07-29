use crate::commands::Execute;
use disguise::Language;

#[derive(clap::Parser, Debug)]
pub struct TransformCommand {
    /// The mnemonic to transform.
    #[clap(value_name = "MNEMONIC")]
    pub mnemonic: String,

    /// The target language for the mnemonic.
    #[clap(hide = true, long = "target")]
    pub language: Option<Language>,

    /// The password to encrypt the mnemonic.
    #[clap(hide = true, long = "password")]
    pub password: Option<String>,
}

// encrypt mnemonic entropy.
// generate a mnemonic from new entropy.

impl Execute for TransformCommand {
    fn execute(&self) -> anyhow::Result<()> {
        // let mnemonic = Mnemonic::from_str(&self.mnemonic)?;
        // let language = match self.language {
        //     Some(lang) => lang,
        //     None => select_language(&Language::all())?,
        // };
        // let mnemonic_transformed = encrypt_mnemonic(&mnemonic, language)?;
        // println!("Transformed mnemonic: {}", mnemonic_transformed.to_string());
        Ok(())
    }
}
