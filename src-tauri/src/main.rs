// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;
use std::{env, thread};

use anyhow::{Context, Result};
use clap::Parser;
use otadump::core::ExtractOptions;
use otadump::{cli, gui};
use tauri::AppHandle;

#[tauri::command]
fn extract(app: AppHandle, payload_file: PathBuf, output_dir: PathBuf) {
    thread::spawn(move || {
        let options = ExtractOptions { payload_file, output_dir };
        gui::extract(app, options);
    });
}

const HELP_TEMPLATE: &str = color_print::cstr!("\
{before-help}<bold><underline>{name} {version}</underline></bold>
{author}
https://github.com/ajeetdsouza/zoxide

{about}

{usage-heading}
{tab}{usage}

{all-args}{after-help}

<bold><underline>Environment variables:</underline></bold>
{tab}<bold>_ZO_DATA_DIR</bold>        {tab}Path for zoxide data files
{tab}<bold>_ZO_ECHO</bold>            {tab}Print the matched directory before navigating to it when set to 1
{tab}<bold>_ZO_EXCLUDE_DIRS</bold>    {tab}List of directory globs to be excluded
{tab}<bold>_ZO_FZF_OPTS</bold>        {tab}Custom flags to pass to fzf
{tab}<bold>_ZO_MAXAGE</bold>          {tab}Maximum total age after which entries start getting deleted
{tab}<bold>_ZO_RESOLVE_SYMLINKS</bold>{tab}Resolve symlinks when storing paths");

#[derive(Debug, Parser)]
#[clap(
    about,
    author,
    help_template = HELP_TEMPLATE,
    disable_help_subcommand = true,
    propagate_version = true,
    version,
)]
struct Args {
    /// Path to the payload file
    #[clap(required = true)]
    payload_file: String,

    /// Path to the output directory
    #[clap(long)]
    output_dir: String,
}

fn main() -> Result<()> {
    // If there are no args, start the GUI. Else, treat it as a command-line
    // invocation.
    if env::args_os().count() <= 1 {
        tauri::Builder::default()
            .invoke_handler(tauri::generate_handler![extract])
            .run(tauri::generate_context!())
            .context("Error running application")
    } else {
        let args = Args::parse();
        let options = ExtractOptions {
            payload_file: args.payload_file.into(),
            output_dir: args.output_dir.into(),
        };
        cli::extract(options);
        Ok(())
    }
}
