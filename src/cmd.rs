use std::borrow::Cow;
use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::ops::{Div, Mul};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::{env, fmt, slice};

use anyhow::{bail, ensure, Context, Result};
use bzip2::read::BzDecoder;
use chrono::Utc;
use clap::{Parser, ValueHint};
use console::Style;
use indicatif::{
    HumanBytes, MultiProgress, ProgressBar, ProgressDrawTarget, ProgressState, ProgressStyle,
};
use lzma::LzmaReader;
use memmap2::{Mmap, MmapMut};
use prost::Message;
use rayon::{ThreadPool, ThreadPoolBuilder};
use sha2::{Digest, Sha256};
use sync_unsafe_cell::SyncUnsafeCell;
use zip::result::ZipError;
use zip::ZipArchive;

use crate::chromeos_update_engine::install_operation::Type;
use crate::chromeos_update_engine::{DeltaArchiveManifest, InstallOperation, PartitionUpdate};
use crate::payload::Payload;

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
const BAR_TEMPLATE: &str = "{prefix:>12.cyan.bold} [{bar:25}] {percent_custom:>4}{wide_msg}";

#[derive(Debug, Parser)]
#[clap(
    about,
    author,
    disable_help_subcommand = true,
    help_template = HELP_TEMPLATE,
    propagate_version = true,
    version = env!("CARGO_PKG_VERSION"),
)]
pub struct Cmd {
    /// OTA file, either a .zip file or a payload.bin.
    #[clap(value_hint = ValueHint::FilePath, value_name = "PATH")]
    payload: PathBuf,

    /// List partitions instead of extracting them
    #[clap(
        conflicts_with = "concurrency",
        conflicts_with = "output_dir",
        conflicts_with = "partitions",
        conflicts_with = "no_verify",
        long,
        short
    )]
    list: bool,

    /// Number of threads to use during extraction
    #[clap(long, short, value_name = "N")]
    concurrency: Option<usize>,

    /// Set output directory
    #[clap(long, short, value_hint = ValueHint::DirPath, value_name = "PATH")]
    output_dir: Option<PathBuf>,

    /// Dump only selected partitions (comma-separated)
    #[clap(long, value_delimiter = ',', value_name = "PARTITIONS")]
    partitions: Vec<String>,

    /// Skip file verification (dangerous!)
    #[clap(long)]
    no_verify: bool,
}

impl Cmd {
    pub fn run(&self) -> Result<()> {
        let payload = self.open_payload_file()?;
        let payload = &Payload::parse(&payload)?;

        let mut manifest =
            DeltaArchiveManifest::decode(payload.manifest).context("unable to parse manifest")?;
        if !self.partitions.is_empty() {
            // Remove any partitions that are not required.
            manifest.partitions.retain(|update: &PartitionUpdate| {
                self.partitions.contains(&update.partition_name)
            });
            // Check that all required partitions are present.
            for partition in &self.partitions {
                if !manifest.partitions.iter().any(|p| &p.partition_name == partition) {
                    bail!("partition {partition:?} not found in manifest");
                }
            }
        }
        let block_size = manifest.block_size.context("block_size not defined")? as usize;

        // If the list flag is set, print the list of partitions and exit.
        if self.list {
            Self::print_partition_list(&mut manifest);
            return Ok(());
        }

        // The largest partitions should be extracted first, because they take the longest to
        // verify.
        manifest.partitions.sort_unstable_by_key(|partition| {
            Reverse(partition.new_partition_info.as_ref().and_then(|info| info.size).unwrap_or(0))
        });

        let partition_dir = self.create_partition_dir()?;
        let partition_dir = partition_dir.as_ref();

        let progress = Arc::new(PartitionProgress::new(&manifest, !self.no_verify));

        let threadpool = self.get_threadpool()?;
        threadpool.scope_fifo(|scope| -> Result<()> {
            for update in &manifest.partitions {
                let (partition_file, partition_size) =
                    Self::open_partition_file(update, partition_dir)?;
                let remaining_ops = Arc::new(AtomicUsize::new(update.operations.len()));

                for (idx, op) in update.operations.iter().enumerate() {
                    let partition_file = Arc::clone(&partition_file);
                    let remaining_ops = Arc::clone(&remaining_ops);
                    let progress = Arc::clone(&progress);

                    scope.spawn_fifo(move |_| {
                        if idx == 0 {
                            progress.set_state(&update.partition_name, PartitionState::Extracting);
                        }

                        let partition = unsafe { (*partition_file.get()).as_mut_ptr() };
                        self.run_op(op, payload, partition, partition_size, block_size)
                            .expect("error running operation");
                        progress.inc_extracting(1);

                        // If this is the last operation of the partition,
                        // verify the output.
                        if remaining_ops.fetch_sub(1, Ordering::AcqRel) == 1 {
                            if !self.no_verify {
                                if let Some(hash) = update
                                    .new_partition_info
                                    .as_ref()
                                    .and_then(|info| info.hash.as_ref())
                                {
                                    progress.set_state(
                                        &update.partition_name,
                                        PartitionState::Verifying,
                                    );
                                    let partition = unsafe { (*partition_file.get()).as_ref() };
                                    self.verify_sha256_with_progress(partition, hash, &progress)
                                        .expect("output verification failed");
                                }
                            }

                            progress.set_state(&update.partition_name, PartitionState::Completed);
                        }
                    });
                }
            }
            Ok(())
        })
    }

    fn print_partition_list(manifest: &mut DeltaArchiveManifest) {
        manifest.partitions.sort_unstable_by(|p1, p2| p1.partition_name.cmp(&p2.partition_name));
        for partition in &manifest.partitions {
            let size = partition
                .new_partition_info
                .as_ref()
                .and_then(|info| info.size)
                .map(|size| HumanBytes(size).to_string());
            let size = size.as_deref().unwrap_or("???");

            let bold_green = Style::new().green().bold();
            println!("{} ({size})", bold_green.apply_to(&partition.partition_name));
        }
    }

    fn run_op(
        &self,
        op: &InstallOperation,
        payload: &Payload,
        partition: *mut u8,
        partition_size: usize,
        block_size: usize,
    ) -> Result<()> {
        let mut dst_extents = Self::extract_dst_extents(op, partition, partition_size, block_size)
            .context("error extracting dst_extents")?;

        match Type::from_i32(op.r#type) {
            Some(Type::Replace) => {
                let mut data = self.extract_data(op, payload).context("error extracting data")?;
                Self::run_op_replace(&mut data, &mut dst_extents, block_size)
                    .context("error in REPLACE operation")
            }
            Some(Type::ReplaceBz) => {
                let data = self.extract_data(op, payload).context("error extracting data")?;
                let mut decoder = BzDecoder::new(data);
                Self::run_op_replace(&mut decoder, &mut dst_extents, block_size)
                    .context("error in REPLACE_BZ operation")
            }
            Some(Type::ReplaceXz) => {
                let data = self.extract_data(op, payload).context("error extracting data")?;
                let mut decoder = LzmaReader::new_decompressor(data)
                    .context("unable to initialize lzma decoder")?;
                Self::run_op_replace(&mut decoder, &mut dst_extents, block_size)
                    .context("error in REPLACE_XZ operation")
            }
            Some(Type::Zero) => Ok(()), // This is a no-op since the partition is already zeroed
            Some(op) => bail!("unimplemented operation: {op:?}"),
            None => bail!("invalid operation"),
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
            bytes_read += io::copy(reader, extent).context("failed to write to buffer")? as usize;
        }
        ensure!(reader.bytes().next().is_none(), "read fewer bytes than expected");

        // Align number of bytes read to block size. The formula for alignment is:
        // ((operand + alignment - 1) / alignment) * alignment
        let bytes_read_aligned = (bytes_read + block_size - 1).div(block_size).mul(block_size);
        ensure!(bytes_read_aligned == dst_len, "more dst blocks than data, even with padding");

        Ok(())
    }

    fn open_payload_file(&self) -> Result<Mmap> {
        let path = &self.payload;
        let file = File::open(path)
            .with_context(|| format!("unable to open file for reading: {path:?}"))?;

        // Assume the file is a zip archive. If it's not, we get an InvalidArchive error, and we can
        // treat it as a payload.bin file.
        match ZipArchive::new(&file) {
            Ok(mut archive) => {
                let mut zipfile = archive
                    .by_name("payload.bin")
                    .context("could not find payload.bin file in archive")?;

                let file_size = zipfile.size();
                let file = tempfile::tempfile().context("failed to create temporary file")?;
                let _ = file.set_len(file_size);

                let style = ProgressStyle::with_template(BAR_TEMPLATE)
                    .expect("template error when constructing progress bar")
                    .progress_chars("=> ")
                    .with_key("percent_custom", percent_custom);
                let bar = ProgressBar::new(file_size)
                    .with_style(style)
                    .with_prefix("Unzipping")
                    .with_message(": payload.bin");
                let line =
                    format!("{:>12} payload.bin", console::style("Unzipping").green().bold(),);
                bar.println(line);

                let mut writer = bar.wrap_write(&file);
                io::copy(&mut zipfile, &mut writer).context("failed to write to temporary file")?;
                bar.finish_and_clear();

                unsafe { Mmap::map(&file) }.context("failed to mmap temporary file")
            }
            Err(ZipError::InvalidArchive(_)) => unsafe { Mmap::map(&file) }
                .with_context(|| format!("failed to mmap file: {path:?}")),
            Err(e) => Err(e).context("failed to open zip archive"),
        }
    }

    fn open_partition_file(
        update: &PartitionUpdate,
        partition_dir: impl AsRef<Path>,
    ) -> Result<(Arc<SyncUnsafeCell<MmapMut>>, usize)> {
        let partition_size = update
            .new_partition_info
            .as_ref()
            .and_then(|info| info.size)
            .context("unable to determine output file size")?;

        let filename = Path::new(&update.partition_name).with_extension("img");
        let path = &partition_dir.as_ref().join(filename);

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
            .with_context(|| format!("unable to open file for writing: {path:?}"))?;
        file.set_len(partition_size)?;
        let mmap = unsafe { MmapMut::map_mut(&file) }
            .with_context(|| format!("failed to mmap file: {path:?}"))?;

        let partition = Arc::new(SyncUnsafeCell::new(mmap));
        Ok((partition, partition_size as usize))
    }

    fn extract_data<'a>(&self, op: &InstallOperation, payload: &'a Payload) -> Result<&'a [u8]> {
        let data_len = op.data_length.context("data_length not defined")? as usize;
        let data = {
            let offset = op.data_offset.context("data_offset not defined")? as usize;
            payload
                .data
                .get(offset..offset + data_len)
                .context("data offset exceeds payload size")?
        };
        match &op.data_sha256_hash {
            Some(hash) if !self.no_verify => {
                Self::verify_sha256(data, hash).context("input verification failed")?;
            }
            _ => {}
        }
        Ok(data)
    }

    fn extract_dst_extents(
        op: &InstallOperation,
        partition: *mut u8,
        partition_size: usize,
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
                    partition_offset + extent_len <= partition_size,
                    "extent exceeds partition size"
                );
                let extent = unsafe {
                    slice::from_raw_parts_mut(partition.add(partition_offset), extent_len)
                };

                Ok(extent)
            })
            .collect()
    }

    fn verify_sha256(data: &[u8], exp_hash: &[u8]) -> Result<()> {
        let got_hash = Sha256::digest(data);
        ensure!(
            got_hash.as_slice() == exp_hash,
            "hash mismatch: expected {}, got {got_hash:x}",
            hex::encode(exp_hash)
        );
        Ok(())
    }

    fn verify_sha256_with_progress(
        &self,
        data: &[u8],
        exp_hash: &[u8],
        progress: &PartitionProgress,
    ) -> Result<()> {
        const CHUNK_SIZE: usize = 4 * 1024 * 1024; // 4 MiB

        let mut sha256 = Sha256::new();
        for chunk in data.chunks(CHUNK_SIZE) {
            sha256.update(chunk);
            progress.inc_verifying(chunk.len() as u64);
        }

        let got_hash = sha256.finalize();
        ensure!(
            got_hash.as_slice() == exp_hash,
            "hash mismatch: expected {}, got {got_hash:x}",
            hex::encode(exp_hash)
        );
        Ok(())
    }

    fn create_partition_dir(&self) -> Result<Cow<PathBuf>> {
        let dir = match &self.output_dir {
            Some(dir) => Cow::Borrowed(dir),
            None => {
                let now = Utc::now();
                let current_dir = env::current_dir().context("please specify --output-dir")?;
                let filename = format!("{}", now.format("extracted_%Y%m%d_%H%M%S"));
                Cow::Owned(current_dir.join(filename))
            }
        };
        fs::create_dir_all(dir.as_ref())
            .with_context(|| format!("could not create output directory: {dir:?}"))?;
        Ok(dir)
    }

    fn get_threadpool(&self) -> Result<ThreadPool> {
        let concurrency = self.concurrency.unwrap_or(0);
        ThreadPoolBuilder::new()
            .num_threads(concurrency)
            .build()
            .context("unable to start threadpool")
    }
}

fn percent_custom(state: &ProgressState, writer: &mut dyn fmt::Write) {
    let percent = (state.fraction() * 100.).floor();
    write!(writer, "{percent}%").unwrap();
}

struct PartitionProgress {
    meta: Mutex<BTreeMap<String, PartitionMeta>>,
    bar_extracting: ProgressBar,
    bar_verifying: Option<ProgressBar>,
}

impl PartitionProgress {
    fn new(manifest: &DeltaArchiveManifest, verify: bool) -> Self {
        let meta = manifest
            .partitions
            .iter()
            .map(|update| {
                let name = update.partition_name.clone();
                let meta = PartitionMeta {
                    state: PartitionState::Pending,
                    size: update
                        .new_partition_info
                        .as_ref()
                        .and_then(|info| info.size)
                        .unwrap_or(0),
                };
                (name, meta)
            })
            .collect();

        let multibar = MultiProgress::new();
        let style = ProgressStyle::with_template(BAR_TEMPLATE)
            .expect("template error when constructing progress bar")
            .progress_chars("=> ")
            .with_key("percent_custom", percent_custom);

        let total_ops =
            manifest.partitions.iter().map(|update| update.operations.len()).sum::<usize>();
        let bar_extracting =
            ProgressBar::new(total_ops as u64).with_style(style.clone()).with_prefix("Extracting");
        multibar.add(bar_extracting.clone());

        let bar_verifying = verify.then(|| {
            let total_size = manifest
                .partitions
                .iter()
                .map(|update| match update.new_partition_info.as_ref() {
                    Some(info) if info.hash.is_some() => info.size.unwrap_or(0),
                    _ => 0,
                })
                .sum::<u64>();
            let bar = ProgressBar::new(total_size).with_style(style).with_prefix("Verifying");
            bar.set_draw_target(ProgressDrawTarget::hidden());
            multibar.add(bar.clone());
            bar
        });

        Self { meta: Mutex::new(meta), bar_extracting, bar_verifying }
    }

    fn inc_extracting(&self, delta: u64) {
        self.bar_extracting.inc(delta);
    }

    fn inc_verifying(&self, delta: u64) {
        if let Some(bar_verifying) = &self.bar_verifying {
            bar_verifying.inc(delta);
        }
    }

    fn print_update(&self, verb: &str, name: impl AsRef<str>) {
        let message = format!("{:>12} {}", console::style(verb).green().bold(), name.as_ref());
        self.bar_extracting.println(message);
    }

    fn format_partitions(meta: &BTreeMap<String, PartitionMeta>, state: PartitionState) -> String {
        let mut partitions = meta
            .iter()
            .filter(|(_, meta)| meta.state == state)
            .map(|(name, _)| format!("{name}.img"))
            .collect::<Vec<_>>()
            .join(", ");
        if !partitions.is_empty() {
            partitions.insert_str(0, ": ");
        }
        partitions
    }

    fn set_state(&self, name: &str, state: PartitionState) {
        let mut meta = self.meta.lock().expect("failed to acquire lock");
        meta.get_mut(name).expect("partition not found").state = state;

        let message_extracting = Self::format_partitions(&meta, PartitionState::Extracting);
        self.bar_extracting.set_message(message_extracting);

        if let Some(bar_verifying) = &self.bar_verifying {
            let message_verifying = Self::format_partitions(&meta, PartitionState::Verifying);
            bar_verifying.set_message(message_verifying);
        }

        // The current partition has completed extraction if:
        // - Verification is disabled and the state has been set to completed, or
        // - Verification is enabled and the state has been set to verifying.
        if (self.bar_verifying.is_none() && state == PartitionState::Completed)
            || (self.bar_verifying.is_some() && state == PartitionState::Verifying)
        {
            self.print_update("Extracted", format!("{name}.img"));
        }

        // The current partition has completed verification if:
        // - Verification is enabled and the state has been set to completed.
        if self.bar_verifying.is_some() && state == PartitionState::Completed {
            self.print_update("Verified", format!("{name}.img"));
        }

        // If all partitions are in the verifying or completed state, all partitions have been
        // extracted.
        if meta
            .values()
            .all(|meta| matches!(meta.state, PartitionState::Verifying | PartitionState::Completed))
        {
            self.bar_extracting.finish_and_clear();
        }

        // If all partitions are in the completed state, all partitions have been verified.
        if meta.values().all(|meta| meta.state == PartitionState::Completed) {
            if let Some(bar_verifying) = &self.bar_verifying {
                bar_verifying.finish_and_clear();
            }
            self.print_update(
                "Completed",
                format!(
                    "extraction{}",
                    if self.bar_verifying.is_some() { " + verification" } else { "" }
                ),
            );
        }
    }
}

struct PartitionMeta {
    state: PartitionState,
    size: u64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum PartitionState {
    Pending,
    Extracting,
    Verifying,
    Completed,
}
