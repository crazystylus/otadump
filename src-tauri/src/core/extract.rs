use std::cell::Cell;
use std::cmp::Reverse;
use std::error::Error;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::ops::{Div as _, Mul as _};
use std::path::{Path, PathBuf};
use std::slice;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{bail, ensure, Context as _, Result};
use bzip2::read::BzDecoder;
use lzma::LzmaReader;
use memmap2::{Mmap, MmapMut};
use prost::Message as _;
use rayon::ThreadPoolBuilder;
use sha2::{Digest as _, Sha256};
use sync_unsafe_cell::SyncUnsafeCell;
use zip::result::ZipError;
use zip::ZipArchive;

use crate::core::chromeos_update_engine::install_operation::Type;
use crate::core::chromeos_update_engine::{
    DeltaArchiveManifest, InstallOperation, PartitionUpdate,
};
use crate::core::payload::Payload;
use crate::core::reporter::Reporter;

pub struct ProgressTracker {
    reporter: Box<dyn Reporter>,
    ops: usize,
    state: Mutex<Cell<ProgressTrackerState>>,
}

impl ProgressTracker {
    fn new(reporter: Box<dyn Reporter>, ops: usize) -> Self {
        let state = ProgressTrackerState { is_halted: false, ops_completed: 0 };
        let state = Mutex::new(Cell::new(state));
        Self { reporter, ops, state }
    }

    fn report_progress(&self, ops: usize) {
        let mut state = self.state.lock().expect("Mutex lock failed");
        let state = state.get_mut();
        if state.is_halted {
            return;
        }
        state.ops_completed += ops;
        debug_assert!(state.ops_completed <= self.ops, "completed ops > total ops");
        let progress = state.ops_completed as f64 / self.ops as f64;
        self.reporter.report_progress(progress);
    }

    fn report_complete(&self) {
        let mut state = self.state.lock().expect("Mutex lock failed");
        let state = state.get_mut();
        if state.is_halted {
            return;
        }
        debug_assert_eq!(state.ops_completed, self.ops);
        state.is_halted = true;
        self.reporter.report_complete();
    }

    fn report_error(&self, error: Box<dyn Error>) {
        let mut state = self.state.lock().expect("Mutex lock failed");
        let state = state.get_mut();
        if state.is_halted {
            return;
        }
        state.is_halted = true;
        self.reporter.report_error(error);
    }
}

pub struct ProgressTrackerState {
    pub is_halted: bool,
    pub ops_completed: usize,
}

#[derive(Debug)]
pub struct ExtractOptions {
    /// OTA file path, either a .zip file or a payload.bin.
    pub payload_file: PathBuf,

    /// Output directory for the extracted files.
    pub output_dir: PathBuf,
}

impl ExtractOptions {
    const VERIFY_CHUNK_SIZE: usize = 2 * 1024 * 1024; // 2 MiB

    pub fn extract(&self, reporter: Box<dyn Reporter>) {
        reporter.report_progress(0.);

        let payload_file = match Self::open_payload_file(&self.payload_file) {
            Ok(file) => file,
            Err(e) => {
                reporter.report_error(e.into());
                return;
            }
        };

        let payload = &match Payload::parse(&payload_file) {
            Ok(payload) => payload,
            Err(e) => {
                reporter.report_error(e.into());
                return;
            }
        };

        let threadpool =
            match ThreadPoolBuilder::new().build().context("Unable to start threadpool") {
                Ok(threadpool) => threadpool,
                Err(e) => {
                    reporter.report_error(e.into());
                    return;
                }
            };

        let mut manifest = match DeltaArchiveManifest::decode(payload.manifest)
            .context("Unable to parse manifest")
        {
            Ok(manifest) => manifest,
            Err(e) => {
                reporter.report_error(e.into());
                return;
            }
        };
        let extract_ops =
            manifest.partitions.iter().map(|update| update.operations.len()).sum::<usize>();
        let verify_ops = manifest
            .partitions
            .iter()
            .map(|update| {
                let partition_size =
                    update.new_partition_info.as_ref().and_then(|info| info.size).unwrap_or(0)
                        as usize;
                partition_size.div_ceil(Self::VERIFY_CHUNK_SIZE)
            })
            .sum::<usize>();
        let tracker = ProgressTracker::new(reporter, extract_ops + verify_ops);
        let tracker = Arc::new(tracker);

        if let Err(e) = threadpool.in_place_scope_fifo(|scope| -> Result<()> {
            // Verification is slow for large partitions, and cannot be parallelized.
            // Extracting the largest partition first allows us to start verifying
            // it as early as possible.
            manifest.partitions.sort_unstable_by_key(|partition| {
                Reverse(
                    partition.new_partition_info.as_ref().and_then(|info| info.size).unwrap_or(0),
                )
            });
            let block_size = manifest.block_size.context("block_size not defined")? as usize;

            let output_dir = &self.output_dir;
            fs::create_dir_all(output_dir)
                .with_context(|| format!("Could not create output directory: {output_dir:?}"))?;

            for update in &manifest.partitions {
                let partition_file = Self::open_partition_file(update, output_dir)?;
                let partition_len = partition_file.len();
                let partition_file = Arc::new(SyncUnsafeCell::new(partition_file));

                let partition_ops = update.operations.len();
                let partition_ops_completed = Arc::new(AtomicUsize::new(0));

                for op in update.operations.iter() {
                    let partition_file = Arc::clone(&partition_file);
                    let partition_ops_completed = Arc::clone(&partition_ops_completed);
                    let tracker = Arc::clone(&tracker);

                    scope.spawn_fifo(move |_| {
                        let partition = unsafe { (*partition_file.get()).as_mut_ptr() };

                        // Run a single operation.
                        let result =
                            Self::run_op(op, payload, partition, partition_len, block_size)
                                .context("Error running operation");
                        if let Err(e) = result {
                            tracker.report_error(e.into());
                            return;
                        }
                        tracker.report_progress(1);

                        // Return early if this is not the last operation of the partition.
                        let partition_ops_completed =
                            partition_ops_completed.fetch_add(1, Ordering::AcqRel) + 1;
                        if partition_ops_completed != partition_ops {
                            return;
                        }

                        // Flush file to disk.
                        let result = unsafe { (*partition_file.get()).flush() }
                            .context("Error while flushing file to disk");
                        if let Err(e) = result {
                            tracker.report_error(e.into());
                            return;
                        }

                        // Verify output hash (if available).
                        update
                            .new_partition_info
                            .as_ref()
                            .and_then(|info| info.hash.as_ref())
                            .inspect(|hash| {
                                let partition = unsafe { (*partition_file.get()).as_ref() };
                                // let result = Self::verify_sha256_and_report(
                                //     partition,
                                //     hash,
                                //     Arc::clone(&tracker),
                                // )
                                // .context("Output verification failed");
                                // if let Err(e) = result {
                                //     tracker.report_error(e.into());
                                // }
                            });
                    });
                }
            }
            Ok(())
        }) {
            tracker.report_error(e.into());
            return;
        }

        tracker.report_complete();
    }

    fn run_op(
        op: &InstallOperation,
        payload: &Payload,
        partition: *mut u8,
        partition_len: usize,
        block_size: usize,
    ) -> Result<()> {
        let mut dst_extents = Self::extract_dst_extents(op, partition, partition_len, block_size)
            .context("Error extracting dst_extents")?;

        match Type::from_i32(op.r#type) {
            Some(Type::Replace) => {
                let mut data = Self::extract_data(op, payload).context("Error extracting data")?;
                Self::run_op_replace(&mut data, &mut dst_extents, block_size)
                    .context("Error in REPLACE operation")
            }
            Some(Type::ReplaceBz) => {
                let data = Self::extract_data(op, payload).context("Error extracting data")?;
                let mut decoder = BzDecoder::new(data);
                Self::run_op_replace(&mut decoder, &mut dst_extents, block_size)
                    .context("Error in REPLACE_BZ operation")
            }
            Some(Type::ReplaceXz) => {
                let data = Self::extract_data(op, payload).context("Error extracting data")?;
                let mut decoder = LzmaReader::new_decompressor(data)
                    .context("Unable to initialize lzma decoder")?;
                Self::run_op_replace(&mut decoder, &mut dst_extents, block_size)
                    .context("Error in REPLACE_XZ operation")
            }
            Some(Type::Zero) => Ok(()), // This is a no-op since the partition is already zeroed
            Some(op) => bail!("Unimplemented operation: {op:?}"),
            None => bail!("Invalid operation"),
        }
    }

    fn run_op_replace(
        reader: &mut impl Read,
        dst_extents: &mut [&mut [u8]],
        block_size: usize,
    ) -> Result<()> {
        let mut bytes_read = 0usize;

        let dst_len = dst_extents.iter().map(|extent| extent.len()).sum::<usize>();
        for extent in dst_extents.iter_mut() {
            bytes_read += io::copy(reader, extent).context("Failed to write to buffer")? as usize;
        }
        ensure!(reader.bytes().next().is_none(), "Read fewer bytes than expected");

        // Align number of bytes read to block size. The formula for alignment is:
        // ((operand + alignment - 1) / alignment) * alignment
        let bytes_read_aligned = (bytes_read + block_size - 1).div(block_size).mul(block_size);
        ensure!(bytes_read_aligned == dst_len, "More dst blocks than data, even with padding");

        Ok(())
    }

    fn extract_data<'a>(op: &InstallOperation, payload: &'a Payload) -> Result<&'a [u8]> {
        let data_len = op.data_length.context("data_length not defined")? as usize;
        let data = {
            let offset = op.data_offset.context("data_offset not defined")? as usize;
            payload
                .data
                .get(offset..offset + data_len)
                .context("Data offset exceeds payload size")?
        };
        if let Some(hash) = &op.data_sha256_hash {
            Self::verify_sha256(data, hash).context("Input verification failed")?;
        }
        Ok(data)
    }

    fn extract_dst_extents(
        op: &InstallOperation,
        partition: *mut u8,
        partition_len: usize,
        block_size: usize,
    ) -> Result<Vec<&'static mut [u8]>> {
        op.dst_extents
            .iter()
            .map(|extent| {
                let start_block =
                    extent.start_block.context("start_block not defined in extent")? as usize;
                let num_blocks =
                    extent.num_blocks.context("num_blocks not defined in extent")? as usize;

                let partition_offset = start_block * block_size;
                let extent_len = num_blocks * block_size;

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

    fn open_payload_file(path: impl AsRef<Path>) -> Result<Mmap> {
        let path = path.as_ref();
        let file = File::open(path)
            .with_context(|| format!("Failed to open file for reading: {path:?}"))?;

        // Assume the file is a zip archive. If it's not, we get an
        // InvalidArchive error, and we can treat it as a payload.bin file.
        match ZipArchive::new(&file) {
            Ok(mut archive) => {
                // TODO: add progress indicator while zip file is being
                // extracted.
                let mut zipfile = archive
                    .by_name("payload.bin")
                    .context("Could not find payload.bin file in archive")?;

                let mut file = tempfile::tempfile().context("Failed to create temporary file")?;
                let _ = file.set_len(zipfile.size());
                io::copy(&mut zipfile, &mut file).context("Failed to write to temporary file")?;

                unsafe { Mmap::map(&file) }.context("Failed to mmap temporary file")
            }
            Err(ZipError::InvalidArchive(_)) => unsafe { Mmap::map(&file) }
                .with_context(|| format!("Failed to mmap file: {path:?}")),
            Err(e) => Err(e).with_context(|| format!("Failed to open payload file: {path:?}")),
        }
    }

    fn open_partition_file(
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
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| format!("Unable to open file for writing: {path:?}"))?;
        file.set_len(partition_len)?;

        let file = unsafe { MmapMut::map_mut(&file) }
            .with_context(|| format!("Failed to mmap file: {path:?}"))?;
        Ok(file)
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

    fn verify_sha256_and_report(
        data: &[u8],
        exp_hash: &[u8],
        tracker: Arc<ProgressTracker>,
    ) -> Result<()> {
        let mut digest = Sha256::new();
        for chunk in data.chunks(Self::VERIFY_CHUNK_SIZE) {
            digest.update(chunk);
            tracker.report_progress(1);
        }

        let got_hash = Sha256::digest(data);
        ensure!(
            got_hash.as_slice() == exp_hash,
            "Hash mismatch: expected {}, got {got_hash:x}",
            hex::encode(exp_hash)
        );
        Ok(())
    }
}
