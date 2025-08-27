use crate::commands::Execute;

#[derive(clap::Parser, Debug)]
pub struct TransformCommand {
    /// The mnemonic to transform.
    #[clap(value_name = "<MNEMONIC|PRIVATE KEY>")]
    pub mnemonic: String,

    #[command(flatten)]
    pub target: Target,

    /// Option password to decrypt wif.
    #[clap(hide = true, long = "password")]
    pub password: Option<String>,
}

#[derive(clap::Args, Debug)]
#[group(required = false, multiple = false)]
pub struct Target {
    /// Transform to wallet's private key or encrypted private key
    #[clap(long, visible_alias = "wif", value_name = "ENCRYPT")]
    pub wallet: Option<bool>,

    /// Transform to mnemonic
    #[clap(long)]
    pub mnemonic: bool,
}

impl Execute for TransformCommand {
    fn execute(&self) -> anyhow::Result<()> {
        // let mnemonic = Mnemonic::from_str(&self.mnemonic)?;
        // let language = match self.language {
        //     Some(lang) => lang,
        //     None => select_language(Language::all())?,
        // };
        // let mnemonic_transformed = encrypt_mnemonic(&mnemonic, language)?;
        // println!("Transformed mnemonic: {}", mnemonic_transformed.to_string());
        Ok(())
    }
}
