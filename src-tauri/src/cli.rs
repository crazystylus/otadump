use std::error::Error;
use std::path::PathBuf;

use indicatif::{ProgressBar, ProgressStyle};

use crate::core::ExtractOptions;

pub fn extract(options: ExtractOptions) {
    let reporter = Box::new(Reporter::new(&options.output_dir));
    options.extract(reporter);
}

#[derive(Debug)]
struct Reporter {
    output_dir: PathBuf,
    progress_bar: ProgressBar,
}

impl Reporter {
    const PROGRESS_TICKS: usize = 10_000;

    fn new(output_dir: impl Into<PathBuf>) -> Self {
        let style = ProgressStyle::with_template(
            "{prefix:>16!.cyan.bold} [{wide_bar:.white.dim}] {percent:>3.white}%",
        )
        .expect("unable to build progress bar template")
        .progress_chars("=> ");
        let progress_bar = ProgressBar::new(Self::PROGRESS_TICKS as u64)
            .with_prefix("Extracting")
            .with_style(style);
        progress_bar.println("Extracting files...");
        Self { output_dir: output_dir.into(), progress_bar }
    }
}

impl crate::core::Reporter for Reporter {
    fn report_progress(&self, progress: f64) {
        let position = progress * Self::PROGRESS_TICKS as f64;
        self.progress_bar.set_position(position as u64);
    }

    fn report_complete(&self) {
        self.progress_bar.finish_and_clear();
        let message = format!("Extraction complete: {}", self.output_dir.display());
        self.progress_bar.println(message);
    }

    fn report_error(&self, error: Box<dyn Error>) {
        self.progress_bar.finish_and_clear();
        let message = format!("Error: {error:?}");
        self.progress_bar.println(message);
    }
}
