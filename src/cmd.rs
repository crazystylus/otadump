use std::borrow::Cow;
use std::cmp::Reverse;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::ops::{Div, Mul};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::{env, slice};

use anyhow::{bail, ensure, Context, Result};
use bzip2::read::BzDecoder;
use chrono::Utc;
use clap::{Parser, ValueHint};
use console::Style;
use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressFinish, ProgressStyle};
use lzma::LzmaReader;
use memmap2::{Mmap, MmapMut};
use prost::Message;
use rayon::{ThreadPool, ThreadPoolBuilder};
use sha2::{Digest, Sha256};
use sync_unsafe_cell::SyncUnsafeCell;

use crate::chromeos_update_engine::install_operation::Type;
use crate::chromeos_update_engine::{DeltaArchiveManifest, InstallOperation, PartitionUpdate};
use crate::payload::Payload;

const HELP_TEMPLATE: &str = "\
{before-help}{name} {version}
{author-with-newline}{about-with-newline}
{usage-heading} {usage}

{all-args}{after-help}
";

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
    /// Payload file
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

    /// Skip input file verification (dangerous!)
    #[clap(long)]
    no_verify: bool,
}

impl Cmd {
    pub fn run(&self) -> Result<()> {
        let payload = self.open_payload_file()?;
        let payload = &Payload::parse(&payload)?;

        let mut manifest =
            DeltaArchiveManifest::decode(payload.manifest).context("unable to parse manifest")?;
        let block_size = manifest.block_size.context("block_size not defined")? as usize;

        if self.list {
            manifest
                .partitions
                .sort_unstable_by(|p1, p2| p1.partition_name.cmp(&p2.partition_name));
            for partition in &manifest.partitions {
                let size = partition
                    .new_partition_info
                    .as_ref()
                    .and_then(|info| info.size)
                    .map(|size| indicatif::HumanBytes(size).to_string());
                let size = size.as_deref().unwrap_or("???");

                let bold_green = Style::new().bold().green();
                println!("{} ({size})", bold_green.apply_to(&partition.partition_name));
            }
            return Ok(());
        }

        for partition in &self.partitions {
            if !manifest.partitions.iter().any(|p| &p.partition_name == partition) {
                bail!("partition \"{}\" not found in manifest", partition);
            }
        }

        manifest.partitions.sort_unstable_by_key(|partition| {
            Reverse(partition.new_partition_info.as_ref().and_then(|info| info.size).unwrap_or(0))
        });

        let partition_dir = self.create_partition_dir()?;
        let partition_dir = partition_dir.as_ref();

        let threadpool = self.get_threadpool()?;
        threadpool.scope(|scope| -> Result<()> {
            let multiprogress = {
                // Setting a fixed update frequence reduces flickering.
                let draw_target = ProgressDrawTarget::stderr_with_hz(2);
                MultiProgress::with_draw_target(draw_target)
            };
            for update in manifest.partitions.iter().filter(|update| {
                self.partitions.is_empty() || self.partitions.contains(&update.partition_name)
            }) {
                let progress_bar = self.create_progress_bar(update)?;
                let progress_bar = multiprogress.add(progress_bar);
                let (partition_file, partition_len) =
                    self.open_partition_file(update, partition_dir)?;
                let remaining_ops = Arc::new(AtomicUsize::new(update.operations.len()));

                for op in update.operations.iter() {
                    let progress_bar = progress_bar.clone();
                    let partition_file = Arc::clone(&partition_file);
                    let remaining_ops = Arc::clone(&remaining_ops);

                    scope.spawn(move |_| {
                        let partition = unsafe { (*partition_file.get()).as_mut_ptr() };
                        self.run_op(op, payload, partition, partition_len, block_size)
                            .expect("error running operation");
                        progress_bar.inc(1);

                        // If this is the last operation of the partition,
                        // verify the output.
                        if !self.no_verify && remaining_ops.fetch_sub(1, Ordering::AcqRel) == 1 {
                            if let Some(hash) = update
                                .new_partition_info
                                .as_ref()
                                .and_then(|info| info.hash.as_ref())
                            {
                                let partition = unsafe { (*partition_file.get()).as_ref() };
                                self.verify_sha256(partition, hash)
                                    .expect("output verification failed");
                            }
                        }
                    });
                }
            }
            Ok(())
        })
    }

    fn create_progress_bar(&self, update: &PartitionUpdate) -> Result<ProgressBar> {
        let finish = ProgressFinish::AndLeave;
        let style = ProgressStyle::with_template(
            "{prefix:>16!.green.bold} [{wide_bar:.white.dim}] {percent:>3.white}%",
        )
        .context("unable to build progress bar template")?
        .progress_chars("=> ");
        let bar = ProgressBar::new(update.operations.len() as u64)
            .with_finish(finish)
            .with_prefix(update.partition_name.to_string())
            .with_style(style);
        Ok(bar)
    }

    fn run_op(
        &self,
        op: &InstallOperation,
        payload: &Payload,
        partition: *mut u8,
        partition_len: usize,
        block_size: usize,
    ) -> Result<()> {
        let mut dst_extents = self
            .extract_dst_extents(op, partition, partition_len, block_size)
            .context("error extracting dst_extents")?;

        match Type::from_i32(op.r#type) {
            Some(Type::Replace) => {
                let mut data = self.extract_data(op, payload).context("error extracting data")?;
                self.run_op_replace(&mut data, &mut dst_extents, block_size)
                    .context("error in REPLACE operation")
            }
            Some(Type::ReplaceBz) => {
                let data = self.extract_data(op, payload).context("error extracting data")?;
                let mut decoder = BzDecoder::new(data);
                self.run_op_replace(&mut decoder, &mut dst_extents, block_size)
                    .context("error in REPLACE_BZ operation")
            }
            Some(Type::ReplaceXz) => {
                let data = self.extract_data(op, payload).context("error extracting data")?;
                let mut decoder = LzmaReader::new_decompressor(data)
                    .context("unable to initialize lzma decoder")?;
                self.run_op_replace(&mut decoder, &mut dst_extents, block_size)
                    .context("error in REPLACE_XZ operation")
            }
            Some(Type::Zero) => Ok(()), // This is a no-op since the partition is already zeroed
            Some(op) => bail!("unimplemented operation: {op:?}"),
            None => bail!("invalid operation"),
        }
    }

    fn run_op_replace(
        &self,
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
        unsafe { Mmap::map(&file) }.with_context(|| format!("failed to mmap file: {path:?}"))
    }

    fn open_partition_file(
        &self,
        update: &PartitionUpdate,
        partition_dir: impl AsRef<Path>,
    ) -> Result<(Arc<SyncUnsafeCell<MmapMut>>, usize)> {
        let partition_len = update
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
        file.set_len(partition_len)?;
        let mmap = unsafe { MmapMut::map_mut(&file) }
            .with_context(|| format!("failed to mmap file: {path:?}"))?;

        let partition = Arc::new(SyncUnsafeCell::new(mmap));
        Ok((partition, partition_len as usize))
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
                self.verify_sha256(data, hash).context("input verification failed")?;
            }
            _ => {}
        }
        Ok(data)
    }

    fn extract_dst_extents(
        &self,
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
                    "extent exceeds partition size"
                );
                let extent = unsafe {
                    slice::from_raw_parts_mut(partition.add(partition_offset), extent_len)
                };

                Ok(extent)
            })
            .collect()
    }

    fn verify_sha256(&self, data: &[u8], exp_hash: &[u8]) -> Result<()> {
        let got_hash = Sha256::digest(data);
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
