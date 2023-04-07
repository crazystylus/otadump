mod chromeos_update_engine {
    include!(concat!(env!("OUT_DIR"), "/chromeos_update_engine.rs"));
}

mod cmd;
mod payload;

use crate::cmd::Cmd;
use anyhow::Result;
use clap::Parser;

fn main() -> Result<()> {
    Cmd::parse().run()
}
