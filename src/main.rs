use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[arg(short, long)]
    translate: String,
}

fn main() {
    let args = Cli::parse();
    println!("{args:?}");
}
