use std::sync::Arc;

use clap::Parser;
use input::Args;
pub use scanner::PortKind;

use tokio;

use crate::{prober::ProbeRegistry, scanner::Scanner};


mod input;
mod scanner;
mod prober;

#[tokio::main]
async fn main() -> Result<(), String> {
    let args = Args::parse();

    let probe_registry = Arc::new(ProbeRegistry::new()?);

    let prober_clones = probe_registry.clone();
    let scanners = args.to_scanners(prober_clones)?;

    ProbeRegistry::new()?;

    for scn in scanners {
        scn.print_result(scn.execute().await).await;
    };

    Ok(())
}
