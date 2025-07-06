#[derive(clap::Parser, Debug)]
pub struct TranslateCommand {
    /// The mnemonic to translate.
    #[clap(value_name = "MNEMONIC")]
    pub mnemonic: String,

    /// The target language for the translation.
    #[clap(hide = true, value_name = "LANGUAGE")]
    pub target: Option<String>,
}

// create a mnemonic from words.
// get indices of the mnemonic words.
// map indices to the target language words.
// return the translated mnemonic as a string.
