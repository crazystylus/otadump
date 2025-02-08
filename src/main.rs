use anyhow::Result;
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use otadump::{ExtractOptions, ProgressReporter};

fn main() -> Result<()> {
    extract();
    Ok(())
}

const HELP_TEMPLATE: &str = color_print::cstr!(
    "\
{before-help}<bold><underline>{name} {version}</underline></bold>
{author}
https://github.com/crazystylus/otadump

{about}

{usage-heading}
{tab}{usage}

{all-args}{after-help}"
);

#[derive(Debug, Parser)]
#[clap(
    about,
    author,
    help_template = HELP_TEMPLATE,
    disable_help_subcommand = true,
    propagate_version = true,
    version,
)]
pub struct Args {
    /// Path to the payload file
    #[clap(required = true)]
    pub payload_file: String,

    /// Path to the output directory
    #[clap(long)]
    pub output_dir: String,
}

pub fn extract() {
    let args = Args::parse();

    let reporter = Box::new(CliProgressReporter::new());
    let reporter = reporter.as_ref();

    let result = ExtractOptions::new()
        .progress_reporter(reporter)
        .extract(&args.payload_file, &args.output_dir);
    reporter.progress_bar.finish_and_clear();
    match result {
        Ok(()) => {
            let message = format!("Extraction complete: {}", args.output_dir);
            reporter.progress_bar.println(message);
        }
        Err(e) => {
            let message = format!("Error: {e:?}");
            reporter.progress_bar.println(message);
        }
    }
}

#[derive(Debug)]
struct CliProgressReporter {
    progress_bar: ProgressBar,
}

impl CliProgressReporter {
    const PROGRESS_TICKS: usize = 10_000;

    fn new() -> Self {
        let style = ProgressStyle::with_template(
            "{prefix:>16!.cyan.bold} [{wide_bar:.white.dim}] {percent:>3.white}%",
        )
        .expect("unable to build progress bar template")
        .progress_chars("=> ");
        let progress_bar = ProgressBar::new(Self::PROGRESS_TICKS as u64)
            .with_prefix("Extracting")
            .with_style(style);
        progress_bar.println("Extracting files...");
        Self { progress_bar }
    }
}

impl ProgressReporter for CliProgressReporter {
    fn report_progress(&self, progress: f64) {
        let position = progress * Self::PROGRESS_TICKS as f64;
        self.progress_bar.set_position(position as u64);
    }
}
