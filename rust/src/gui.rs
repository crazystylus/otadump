use std::error::Error;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager as _};

use crate::core::ExtractOptions;

pub fn extract(app: AppHandle, options: ExtractOptions) {
    let reporter = Reporter::new(app);
    options.extract(Box::new(reporter));
}

#[derive(Debug)]
struct Reporter {
    app: AppHandle,
}

impl Reporter {
    const EVENT_NAME: &'static str = "reporter";

    fn new(app: AppHandle) -> Self {
        Self { app }
    }

    fn emit_all(&self, message: Message) {
        if let Err(e) = self.app.emit_all(Self::EVENT_NAME, message) {
            eprintln!("failed to emit message: {}", e);
        }
    }
}

impl crate::core::Reporter for Reporter {
    fn report_progress(&self, progress: f64) {
        let message = Message::Progress { value: progress };
        self.emit_all(message);
    }

    fn report_complete(&self) {
        let message = Message::Completed;
        self.emit_all(message);
    }

    fn report_error(&self, error: Box<dyn Error>) {
        let error = format!("{:?}", error);
        let message = Message::Error { message: error };
        self.emit_all(message);
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "kind")]
enum Message {
    Progress { value: f64 },
    Completed,
    Error { message: String },
}
