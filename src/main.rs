use clap::Parser;
use input::Args;
pub use scanner::PortKind;
use tokio;

use crate::scanner::Scanner;


mod input;
mod scanner;
mod prober;

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let scanners = args.to_scanners().unwrap();

    for scn in scanners {
        scn.print_result(scn.scan().await).await;
    }
}
