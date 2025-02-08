#[allow(clippy::all)]
mod chromeos_update_engine {
    include!(concat!(env!("OUT_DIR"), "/chromeos_update_engine.rs"));
}
mod payload;

use std::cmp::Reverse;
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::num::NonZero;
use std::ops::{Div as _, Mul as _};
use std::path::Path;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{error, result, slice, thread};

use anyhow::{Context as _, Error, Result, bail, ensure};
use bzip2::read::BzDecoder;
use chromeos_update_engine::install_operation::Type;
use chromeos_update_engine::{DeltaArchiveManifest, InstallOperation, PartitionUpdate};
use liblzma::read::XzDecoder;
use memmap2::{Mmap, MmapMut};
use prost::Message as _;
use rayon::{BroadcastContext, ThreadPoolBuilder};
use sha2::{Digest as _, Sha256};
use sync_unsafe_cell::SyncUnsafeCell;
use zip::ZipArchive;
use zip::result::ZipError;

pub use crate::payload::Payload;

// The chunk size is the number of bytes we verify before we count one "tick" in
// the progress tracker.
const VERIFY_CHUNK_SIZE: usize = 2 * 1024 * 1024; // 2 MiB

pub struct ExtractOptions<'a> {
    num_threads: Option<usize>,
    overwrite: bool,
    partitions: Option<HashSet<String>>,
    progress_reporter: &'a dyn ProgressReporter,
    verify: bool,
}

impl<'a> ExtractOptions<'a> {
    /// Creates a blank new set of options ready for configuration.
    pub fn new() -> Self {
        Self {
            num_threads: None,
            overwrite: false,
            partitions: None,
            progress_reporter: &NoOpProgressReporter,
            verify: true,
        }
    }

    /// Extracts the payload file to the output directory.
    pub fn extract<P, Q>(
        &self,
        payload_file: P,
        output_dir: Q,
    ) -> result::Result<(), Box<dyn error::Error>>
    where
        P: AsRef<Path>,
        Q: AsRef<Path>,
    {
        let payload_file = payload_file.as_ref();
        let output_dir = output_dir.as_ref();
        self.extract_impl(payload_file, output_dir)?;
        Ok(())
    }

    fn extract_impl(&self, payload_file: &Path, output_dir: &Path) -> Result<()> {
        self.progress_reporter.report_progress(0.);

        let payload_file = Self::open_payload_file(payload_file)?;
        let payload = Payload::parse(&payload_file)?;

        let mut manifest =
            DeltaArchiveManifest::decode(payload.manifest).context("Unable to parse manifest")?;

        // Skip partitions that are not in the list of partitions to be extracted.
        if let Some(partitions) = &self.partitions {
            manifest.partitions.retain(|update| partitions.contains(&update.partition_name));
        }

        // Verification is slow for large partitions, and cannot be parallelized.
        // Extracting the largest partition first allows us to start verifying
        // it as early as possible.
        manifest.partitions.sort_unstable_by_key(|partition| {
            Reverse(partition.new_partition_info.as_ref().and_then(|info| info.size).unwrap_or(0))
        });

        let extract_ops =
            manifest.partitions.iter().map(|update| update.operations.len()).sum::<usize>();
        let verify_ops = if self.verify {
            manifest
                .partitions
                .iter()
                .map(|update| {
                    let partition_size =
                        update.new_partition_info.as_ref().and_then(|info| info.size).unwrap_or(0)
                            as usize;
                    partition_size.div_ceil(VERIFY_CHUNK_SIZE)
                })
                .sum()
        } else {
            0
        };
        let total_ops = extract_ops + verify_ops;
        let total_ops_completed = AtomicUsize::new(0);

        let block_size = manifest.block_size.context("block_size not defined")? as usize;

        // Ensure that all partitions to be extracted are present in the manifest.
        for partition_name in self.partitions.iter().flatten() {
            ensure!(
                manifest.partitions.iter().any(|update| &update.partition_name == partition_name),
                "Partition not found: {partition_name}",
            );
        }

        fs::create_dir_all(output_dir)
            .with_context(|| format!("Could not create output directory: {output_dir:?}"))?;

        let num_threads = self
            .num_threads
            .unwrap_or_else(|| thread::available_parallelism().map(NonZero::get).unwrap_or(1))
            .max(1);
        let threadpool = ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .build()
            .context("Unable to start threadpool")?;
        let mut error = OnceLock::new();

        threadpool.in_place_scope_fifo(|scope| -> Result<()> {
            for update in &manifest.partitions {
                // Exit early if an error has occurred.
                if error.get().is_some() {
                    break;
                }

                // Create and broadcast a task to the threadpool.
                let partition = self.open_partition_file(update, output_dir)?;
                let task = Task {
                    payload: &payload,
                    block_size,
                    verify: self.verify,
                    update,
                    op_idx: AtomicUsize::new(0),
                    partition: SyncUnsafeCell::new(partition),
                    total_ops,
                    total_ops_completed: &total_ops_completed,
                    progress_reporter: self.progress_reporter,
                    error: &error,
                };
                scope.spawn_broadcast(move |_, ctx| {
                    if let Err(e) = task.run(ctx) {
                        _ = task.error.set(e);
                    }
                });
            }
            Ok(())
        })?;

        if let Some(e) = error.take() {
            return Err(e);
        }

        self.progress_reporter.report_progress(1.);
        Ok(())
    }

    fn open_payload_file(path: &Path) -> Result<Mmap> {
        let file = File::open(path)
            .with_context(|| format!("Failed to open file for reading: {path:?}"))?;

        // Assume the file is a zip archive. If it's not, we get an
        // InvalidArchive error, and we can treat it as a payload.bin file.
        match ZipArchive::new(&file) {
            Ok(mut archive) => {
                let mut zipfile = archive
                    .by_name("payload.bin")
                    .context("Could not find payload.bin file in archive")?;

                let file = tempfile::tempfile().context("Failed to create temporary file")?;
                let _ = file.set_len(zipfile.size());
                let mut file =
                    unsafe { MmapMut::map_mut(&file) }.context("Failed to mmap temporary file")?;

                zipfile.read_exact(&mut file).context("Failed to write to temporary file")?;
                ensure!(
                    zipfile.bytes().next().is_none(),
                    "Failed to extract temporary file: zip reported the wrong uncompressed size"
                );

                file.make_read_only().context("Failed to make temporary file read-only")
            }
            Err(ZipError::InvalidArchive(_)) => unsafe { Mmap::map(&file) }
                .with_context(|| format!("Failed to mmap file: {path:?}")),
            Err(e) => Err(e).with_context(|| format!("Failed to open payload file: {path:?}")),
        }
    }

    fn open_partition_file(
        &self,
        update: &PartitionUpdate,
        partition_dir: impl AsRef<Path>,
    ) -> Result<MmapMut> {
        let partition_len = update
            .new_partition_info
            .as_ref()
            .and_then(|info| info.size)
            .context("Unable to determine output file size")?;

        let filename = Path::new(&update.partition_name).with_extension("img");
        let path = partition_dir.as_ref().join(filename);

        let file = OpenOptions::new()
            .create(true)
            .create_new(!self.overwrite)
            .read(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .with_context(|| format!("Unable to open file for writing: {path:?}"))?;
        file.set_len(partition_len)?;

        let file = unsafe { MmapMut::map_mut(&file) }
            .with_context(|| format!("Failed to mmap file: {path:?}"))?;
        Ok(file)
    }

    /// Number of threads to use for extraction. By default, this is set to the
    /// number of logical CPUs on the system.
    pub fn num_threads(&mut self, num_threads: usize) -> &mut Self {
        self.num_threads = Some(num_threads);
        self
    }

    /// Whether to overwrite existing files when extracting. By default,
    /// existing files are not overwritten.
    pub fn overwrite(&mut self, overwrite: bool) -> &mut Self {
        self.overwrite = overwrite;
        self
    }

    /// Extract only the specified partitions from the payload. By default, all
    /// partitions are extracted.
    pub fn partitions<I, S>(&mut self, partitions: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.partitions =
            Some(partitions.into_iter().map(|partition| partition.as_ref().to_string()).collect());
        self
    }

    /// Set a progress reporter to report extraction progress.
    pub fn progress_reporter(&mut self, progress_reporter: &'a dyn ProgressReporter) -> &mut Self {
        self.progress_reporter = progress_reporter;
        self
    }

    /// Verify the input and output partitions. This is enabled by default.
    pub fn verify(&mut self, verify: bool) -> &mut Self {
        self.verify = verify;
        self
    }
}

impl Default for ExtractOptions<'_> {
    fn default() -> Self {
        Self::new()
    }
}

struct Task<'a> {
    payload: &'a Payload<'a>,
    block_size: usize,
    verify: bool,

    update: &'a PartitionUpdate,
    op_idx: AtomicUsize,
    partition: SyncUnsafeCell<MmapMut>,

    total_ops: usize,
    total_ops_completed: &'a AtomicUsize,
    progress_reporter: &'a dyn ProgressReporter,

    error: &'a OnceLock<Error>,
}

impl Task<'_> {
    fn run(&self, ctx: BroadcastContext<'_>) -> Result<()> {
        // If an error has already occurred, stop processing the partition.
        while self.error.get().is_none() {
            let op_idx = self.op_idx.fetch_add(1, Ordering::AcqRel);
            match self.update.operations.get(op_idx) {
                Some(op) => {
                    self.run_op(op)?;
                    self.increment_progress();
                }
                None => {
                    // If this is the last thread to fetch an operation for this
                    // partition, the partition is fully extracted and can now be
                    // verified.
                    if op_idx + 1 == self.update.operations.len() + ctx.num_threads() {
                        self.verify_partition()?;
                    };

                    // Flush file to disk.
                    unsafe { (*self.partition.get()).flush() }
                        .context("Error while flushing file to disk")?;
                    break;
                }
            }
        }
        Ok(())
    }

    fn run_op(&self, op: &InstallOperation) -> Result<()> {
        let mut dst_extents =
            self.extract_dst_extents(op).context("Error extracting dst_extents")?;

        match Type::try_from(op.r#type).context("Invalid operation")? {
            Type::Replace => {
                let mut data = self.extract_data(op).context("Error extracting data")?;
                self.run_op_replace(&mut data, &mut dst_extents)
                    .context("Error in REPLACE operation")
            }
            Type::ReplaceBz => {
                let data = self.extract_data(op).context("Error extracting data")?;
                let mut decoder = BzDecoder::new(data);
                self.run_op_replace(&mut decoder, &mut dst_extents)
                    .context("Error in REPLACE_BZ operation")
            }
            Type::ReplaceXz => {
                let data = self.extract_data(op).context("Error extracting data")?;
                let mut decoder = XzDecoder::new(data);
                self.run_op_replace(&mut decoder, &mut dst_extents)
                    .context("Error in REPLACE_XZ operation")
            }
            Type::Zero => Ok(()), // This is a no-op since the partition is already zeroed
            op => bail!("Unimplemented operation: {op:?}"),
        }
    }

    fn run_op_replace(&self, reader: &mut impl Read, dst_extents: &mut [&mut [u8]]) -> Result<()> {
        let mut bytes_read = 0usize;

        let dst_len = dst_extents.iter().map(|extent| extent.len()).sum::<usize>();
        for extent in dst_extents.iter_mut() {
            bytes_read += io::copy(reader, extent).context("Failed to write to buffer")? as usize;
        }
        ensure!(reader.bytes().next().is_none(), "Read fewer bytes than expected");

        // Align number of bytes read to block size. The formula for alignment is:
        // ((operand + alignment - 1) / alignment) * alignment
        let bytes_read_aligned =
            (bytes_read + self.block_size - 1).div(self.block_size).mul(self.block_size);
        ensure!(bytes_read_aligned == dst_len, "More dst blocks than data, even with padding");

        Ok(())
    }

    fn extract_dst_extents(&self, op: &InstallOperation) -> Result<Vec<&'static mut [u8]>> {
        let partition = unsafe { (*self.partition.get()).as_mut_ptr() };
        let partition_len = unsafe { (*self.partition.get()).len() };

        op.dst_extents
            .iter()
            .map(|extent| {
                let start_block =
                    extent.start_block.context("start_block not defined in extent")? as usize;
                let num_blocks =
                    extent.num_blocks.context("num_blocks not defined in extent")? as usize;

                let partition_offset = start_block * self.block_size;
                let extent_len = num_blocks * self.block_size;

                ensure!(
                    partition_offset + extent_len <= partition_len,
                    "Extent exceeds partition size"
                );
                let extent = unsafe {
                    slice::from_raw_parts_mut(partition.add(partition_offset), extent_len)
                };

                Ok(extent)
            })
            .collect()
    }

    fn extract_data<'a>(&'a self, op: &InstallOperation) -> Result<&'a [u8]> {
        let data_len = op.data_length.context("data_length not defined")? as usize;
        let data = {
            let offset = op.data_offset.context("data_offset not defined")? as usize;
            self.payload
                .data
                .get(offset..offset + data_len)
                .context("Data offset exceeds payload size")?
        };
        self.verify_op(op, data)?;
        Ok(data)
    }

    fn verify_op(&self, op: &InstallOperation, data: &[u8]) -> Result<()> {
        if !self.verify {
            return Ok(());
        }
        let Some(exp_hash) = &op.data_sha256_hash else {
            return Ok(());
        };

        let got_hash = Sha256::digest(data);
        ensure!(
            got_hash.as_slice() == exp_hash,
            "Input verification failed: hash mismatch: expected {}, got {got_hash:x}",
            hex::encode(exp_hash)
        );
        Ok(())
    }

    fn verify_partition(&self) -> Result<()> {
        if !self.verify {
            return Ok(());
        }

        let Some(exp_hash) =
            self.update.new_partition_info.as_ref().and_then(|info| info.hash.as_ref())
        else {
            return Ok(());
        };

        let mut digest = Sha256::new();
        for chunk in unsafe { (*self.partition.get()).chunks(VERIFY_CHUNK_SIZE) } {
            digest.update(chunk);
            self.increment_progress();
        }

        let got_hash = digest.finalize();
        ensure!(
            got_hash.as_slice() == exp_hash,
            "Output verification failed: hash mismatch: expected {}, got {got_hash:x}",
            hex::encode(exp_hash)
        );
        Ok(())
    }

    fn increment_progress(&self) {
        let total_ops_completed = self.total_ops_completed.fetch_add(1, Ordering::AcqRel) + 1;
        if total_ops_completed % 16 == 0 {
            let progress = total_ops_completed as f64 / self.total_ops as f64;
            self.progress_reporter.report_progress(progress);
        }
    }
}

pub trait ProgressReporter: Sync {
    /// Reports the progress of the extraction process. The progress is provided
    /// as a value between 0 and 1.
    fn report_progress(&self, progress: f64);
}

pub struct NoOpProgressReporter;

impl ProgressReporter for NoOpProgressReporter {
    fn report_progress(&self, _progress: f64) {}
}
