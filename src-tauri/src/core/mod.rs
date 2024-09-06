#[allow(clippy::all)]
mod chromeos_update_engine {
    include!(concat!(env!("OUT_DIR"), "/chromeos_update_engine.rs"));
}
mod extract;
mod payload;
mod reporter;

use std::cmp::Reverse;
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::num::NonZero;
use std::ops::{Div as _, Mul as _};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;
use std::{error, result, slice};

use anyhow::{bail, ensure, Context as _, Error, Result};
use bzip2::read::BzDecoder;
use chromeos_update_engine::install_operation::Type;
use chromeos_update_engine::{DeltaArchiveManifest, InstallOperation, PartitionUpdate};
pub use extract::ExtractOptions;
use lzma::LzmaReader;
use memmap2::{Mmap, MmapMut};
use payload::Payload;
use prost::Message as _;
use rayon::ThreadPoolBuilder;
pub use reporter::Reporter;
use sha2::{Digest as _, Sha256};
use sync_unsafe_cell::SyncUnsafeCell;
use zip::result::ZipError;
use zip::ZipArchive;

pub struct ExtractOptions2 {
    num_threads: Option<usize>,
    overwrite: bool,
    partitions: Option<HashSet<String>>,
    progress_reporter: Box<dyn ProgressReporter>,
}

impl ExtractOptions2 {
    /// Creates a blank new set of options ready for configuration.
    pub fn new() -> Self {
        Self {
            num_threads: None,
            overwrite: false,
            partitions: None,
            progress_reporter: Box::new(NoOpProgressReporter),
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
        // Verification is slow for large partitions, and cannot be parallelized.
        // Extracting the largest partition first allows us to start verifying
        // it as early as possible.
        manifest.partitions.sort_unstable_by_key(|partition| {
            Reverse(partition.new_partition_info.as_ref().and_then(|info| info.size).unwrap_or(0))
        });
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
            .unwrap_or_else(|| std::thread::available_parallelism().map(NonZero::get).unwrap_or(1))
            .max(1);
        let threadpool = ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .build()
            .context("Unable to start threadpool")?;
        let mut error = OnceLock::new();

        threadpool.in_place_scope_fifo(|scope| -> Result<()> {
            for update in &manifest.partitions {
                // Skip partitions that are not in the list of partitions to be extracted.
                if let Some(partitions) = &self.partitions {
                    if !partitions.contains(&update.partition_name) {
                        continue;
                    }
                }

                let partition_file = self.open_partition_file(update, output_dir)?;
                let state = Task {
                    payload: &payload,
                    block_size,
                    update,
                    op_idx: AtomicUsize::new(0),
                    partition_file: SyncUnsafeCell::new(partition_file),
                    error: &error,
                };

                scope.spawn_broadcast(move |_, _| {
                    while state.error.get().is_none() {
                        let op_idx = state.op_idx.fetch_add(1, Ordering::AcqRel);
                        let Some(op) = state.update.operations.get(op_idx) else { break };
                        if let Err(e) = state.run_op(op) {
                            _ = state.error.set(e);
                            break;
                        }
                    }
                });
            }

            Ok(())
        })?;

        match error.take() {
            Some(e) => Err(e),
            None => Ok(()),
        }
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
    pub fn progress_reporter(&mut self, progress_reporter: Box<dyn ProgressReporter>) -> &mut Self {
        self.progress_reporter = progress_reporter;
        self
    }
}

impl Default for ExtractOptions2 {
    fn default() -> Self {
        Self::new()
    }
}

struct Task<'a> {
    payload: &'a Payload<'a>,
    block_size: usize,

    update: &'a PartitionUpdate,
    op_idx: AtomicUsize,

    partition_file: SyncUnsafeCell<MmapMut>,
    error: &'a OnceLock<Error>,
}

impl Task<'_> {
    fn run_op(&self, op: &InstallOperation) -> Result<()> {
        let mut dst_extents =
            self.extract_dst_extents(op).context("Error extracting dst_extents")?;

        match Type::from_i32(op.r#type) {
            Some(Type::Replace) => {
                let mut data = self.extract_data(op).context("Error extracting data")?;
                self.run_op_replace(&mut data, &mut dst_extents)
                    .context("Error in REPLACE operation")
            }
            Some(Type::ReplaceBz) => {
                let data = self.extract_data(op).context("Error extracting data")?;
                let mut decoder = BzDecoder::new(data);
                self.run_op_replace(&mut decoder, &mut dst_extents)
                    .context("Error in REPLACE_BZ operation")
            }
            Some(Type::ReplaceXz) => {
                let data = self.extract_data(op).context("Error extracting data")?;
                let mut decoder = LzmaReader::new_decompressor(data)
                    .context("Unable to initialize lzma decoder")?;
                self.run_op_replace(&mut decoder, &mut dst_extents)
                    .context("Error in REPLACE_XZ operation")
            }
            Some(Type::Zero) => Ok(()), // This is a no-op since the partition is already zeroed
            Some(op) => bail!("Unimplemented operation: {op:?}"),
            None => bail!("Invalid operation"),
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
        let partition_file = self.partition_file.get();
        let partition = unsafe { (*partition_file).as_mut_ptr() };
        let partition_len = unsafe { (*partition_file).len() };

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
        if let Some(hash) = &op.data_sha256_hash {
            Self::verify_sha256(data, hash).context("Input verification failed")?;
        }
        Ok(data)
    }

    fn verify_sha256(data: &[u8], exp_hash: &[u8]) -> Result<()> {
        let got_hash = Sha256::digest(data);
        ensure!(
            got_hash.as_slice() == exp_hash,
            "Hash mismatch: expected {}, got {got_hash:x}",
            hex::encode(exp_hash)
        );
        Ok(())
    }
}

pub trait ProgressReporter {
    /// Reports the progress of the extraction process. The progress is provided
    /// as a value between 0 and 1.
    fn report_progress(&self, progress: f64);
}

struct NoOpProgressReporter;

impl ProgressReporter for NoOpProgressReporter {
    fn report_progress(&self, _progress: f64) {}
}
