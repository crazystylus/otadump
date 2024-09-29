use std::error::Error;

pub trait Reporter: Send + Sync {
    // Reports the overall progress of the task that is running (between 0 and 1).
    fn report_progress(&self, progress: f64);

    // Reports that the task has completed successfully.
    fn report_complete(&self);

    // Reports a fatal error that has halted the task.
    fn report_error(&self, error: Box<dyn Error>);
}
