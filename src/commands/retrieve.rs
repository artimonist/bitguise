#[derive(clap::Parser, Debug)]
pub struct RetrieveCommand {
    /// The name of the article to retrieve.
    #[clap(value_name = "ARTICLE")]
    pub article: String,

    /// The language of the article to retrieve.
    #[clap(hide = true, value_name = "LANGUAGE")]
    pub language: Option<String>,
}
