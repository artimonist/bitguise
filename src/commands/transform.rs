use crate::commands::Execute;

#[derive(clap::Parser, Debug)]
pub struct TransformCommand {
    /// The mnemonic to transform.
    #[clap(value_name = "MNEMONIC")]
    pub mnemonic: String,

    #[clap(flatten)]
    pub target: MnemonicTarget,
}

#[derive(clap::Args, Debug, Clone)]
#[group(required = false, multiple = true)]
pub struct MnemonicTarget {
    /// The target language for the mnemonic.
    #[clap(value_name = "LANGUAGE")]
    pub language: Option<String>,

    #[clap(value_name = "LENGTH", value_parser = ["12", "15", "18", "21", "24"], default_value = "24")]
    pub length: Option<usize>,
}

// encrypt mnemonic entropy.
// generate a mnemonic from new entropy.

impl Execute for TransformCommand {
    fn execute(&self) -> anyhow::Result<()> {
        todo!("Implement the transform command logic");
    }
}
