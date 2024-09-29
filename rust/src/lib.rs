use core::ExtractOptions;
use std::path::PathBuf;
use std::thread;

use tauri::AppHandle;

pub mod cli;
pub mod core;
pub mod gui;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![extract])
        .run(tauri::generate_context!())
        .expect("Error running application")
}

#[tauri::command]
fn extract(app: AppHandle, payload_file: PathBuf, output_dir: PathBuf) {
    thread::spawn(move || {
        let options = ExtractOptions { payload_file, output_dir };
        gui::extract(app, options);
    });
}
