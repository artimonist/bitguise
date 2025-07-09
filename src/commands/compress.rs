use disguise::Language;

/// Compress mnemonic by given dictionary.
#[derive(clap::Parser, Debug)]
pub struct SearchCommand {
    /// The mnemonic to compress
    pub mnemonic: String,

    /// The name of the article as dictionary.
    #[clap(value_name = "FILE")]
    pub article: String,

    /// The language of the article.
    #[clap(hide = true, long = "target")]
    pub language: Option<Language>,

    #[clap(hide = true, long = "password")]
    pub password: Option<String>,
}

// translate mnemonic to target language.
// search mnemonic words in article.
// if article not contains all words, return fail.
// list all words index in article.
// join index bits as entropy.
// generate a new mnemonic.
