use clap::Parser;
use input::Args;
pub use scanner::PortKind;


mod input;
mod scanner;

fn main() {
    let args = Args::parse();

    let scan_cfg = args.to_scan_config().unwrap();

    scan_cfg.scan();
}
