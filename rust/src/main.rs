// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::env;

use anyhow::Result;
use app_lib::cli;

fn main() -> Result<()> {
    // If there are no args, start the GUI. Else, treat it as a command-line
    // invocation.
    if env::args_os().count() <= 1 {
        app_lib::run();
        Ok(())
    } else {
        cli::extract();
        Ok(())
    }

    // struct Reporter;

    // impl otadump::core::ProgressReporter for Reporter {
    //     fn report_progress(&self, progress: f64) {
    //         println!("Progress: {}%", progress * 100.0);
    //     }
    // }

    // let reporter = Box::new(Reporter);

    // ExtractOptions2::new()
    //     .overwrite(true)
    //     .progress_reporter(reporter)
    //     .verify(false)
    //     .extract("/tmp/cbce4b4611f7a10bc02ee2e03872b2f4aa241b9a.zip",
    // "/tmp/asdf")     .unwrap();
    // Ok(())

    // let args = Args::parse();
    // let options = ExtractOptions {
    //     payload_file:
    // "/tmp/cbce4b4611f7a10bc02ee2e03872b2f4aa241b9a.zip".into(),
    //     output_dir: "/tmp/qwer".into(),
    // };
    // cli::extract(options);
    // Ok(())
}
