mod chromeos_update_engine {
    include!(concat!(env!("OUT_DIR"), "/chromeos_update_engine.rs"));
}

mod cmd;
mod payload;

use anyhow::Result;
use clap::Parser;

use crate::cmd::Cmd;

fn main() -> Result<()> {
    Cmd::parse().run()
}
