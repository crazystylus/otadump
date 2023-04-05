pub mod chromeos_update_engine {
    include!(concat!(env!("OUT_DIR"), "/chromeos_update_engine.rs"));
}

mod payload;

use crate::payload::Payload;
use anyhow::{ensure, Context, Result};
use bzip2::read::BzDecoder;
use chromeos_update_engine::install_operation::Type;
use chromeos_update_engine::{DeltaArchiveManifest, InstallOperation};
use indicatif::{MultiProgress, ProgressBar, ProgressFinish, ProgressStyle};
use lzma::LzmaReader;
use memmap2::{Mmap, MmapMut};
use prost::Message;
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::ops::{Div, Mul};
use std::path::Path;
use std::slice;
use std::sync::Arc;
use sync_unsafe_cell::SyncUnsafeCell;

fn read_all(reader: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut total_read = 0;
    while total_read < buf.len() {
        match reader.read(&mut buf[total_read..]) {
            Ok(0) => break,
            Ok(n) => total_read += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(total_read)
}

fn op_replace(
    reader: &mut impl Read,
    dst_extents: &mut [&mut [u8]],
    block_size: usize,
) -> Result<()> {
    let mut bytes_read = 0usize;

    let dst_len = dst_extents.iter().map(|extent| extent.len()).sum::<usize>();
    let (dst_extents_last, dst_extents) = dst_extents.split_last_mut().unwrap();

    for extent in dst_extents.iter_mut() {
        reader
            .read_exact(extent)
            .expect("failed to write to buffer");
        bytes_read += extent.len();
    }
    bytes_read += read_all(reader, dst_extents_last).expect("failed to write to buffer");

    ensure!(
        reader.bytes().next().is_none(),
        "read fewer bytes than expected"
    );

    // Align number of bytes read to block size. The formula for alignment is:
    // ((operand + alignment - 1) / alignment) * alignment
    let bytes_read_aligned = (bytes_read + block_size - 1)
        .div(block_size)
        .mul(block_size);
    ensure!(
        bytes_read_aligned == dst_len,
        "more dst blocks than data, even with padding"
    );

    Ok(())
}

fn main() -> Result<()> {
    let payload_path = "payload.bin";
    let payload = payload_mmap(payload_path)?;
    let payload = Payload::parse(&payload).context("unable to parse payload")?;
    ensure!(
        payload.magic_bytes == b"CrAU",
        "invalid magic bytes: {}",
        hex::encode(payload.magic_bytes)
    );

    let manifest =
        DeltaArchiveManifest::decode(payload.manifest).context("unable to parse manifest")?;
    let block_size = manifest.block_size.context("block_size not defined")? as usize;

    rayon::scope(|scope| -> Result<()> {
        let multiprogress = MultiProgress::new();
        for update in manifest.partitions {
            let partition_path = &format!("tmp/{}.img", update.partition_name);
            let partition_len = update
                .new_partition_info
                .and_then(|info| info.size)
                .context("unable to determine output file size")?;
            let partition = Arc::new(SyncUnsafeCell::new(partition_mmap(
                partition_path,
                partition_len,
            )?));

            let finish = ProgressFinish::AndLeave;
            let style = ProgressStyle::with_template(
                "{prefix:>16!.green.bold} [{wide_bar:.white.dim}] {percent:>3.white}%",
            )
            .expect("unable to build progress bar template")
            .progress_chars("=> ");
            let progress = ProgressBar::new(update.operations.len() as u64)
                .with_finish(finish)
                .with_prefix(update.partition_name)
                .with_style(style);
            let progress = multiprogress.add(progress);

            for op in update.operations {
                let partition = Arc::clone(&partition);
                let progress = progress.clone();

                scope.spawn(move |_| {
                    let data_len = op.data_length.expect("data_length not defined") as usize;
                    let mut data = {
                        let offset = op.data_offset.expect("data_offset not defined") as usize;
                        payload
                            .data
                            .get(offset..offset + data_len)
                            .expect("data offset exceeds payload size")
                    };

                    if let Some(hash) = &op.data_sha256_hash {
                        verify_sha256(data, hash).unwrap();
                    }

                    let partition = unsafe { (*partition.get()).as_mut_ptr() };
                    let mut dst_extents =
                        extract_dst_extents(&op, partition, partition_len as usize, block_size)
                            .expect("error extracting dst_extents");

                    match Type::from_i32(op.r#type) {
                        Some(Type::Replace) => {
                            op_replace(&mut data, &mut dst_extents, block_size)
                                .expect("error in REPLACE operation");
                        }
                        Some(Type::ReplaceBz) => {
                            let mut decoder = BzDecoder::new(data);
                            op_replace(&mut decoder, &mut dst_extents, block_size)
                                .expect("error in REPLACE_BZ operation");
                        }
                        Some(Type::ReplaceXz) => {
                            let mut decoder = LzmaReader::new_decompressor(data)
                                .expect("unable to initialize lzma decoder");
                            op_replace(&mut decoder, &mut dst_extents, block_size)
                                .expect("error in REPLACE_XZ operation");
                        }
                        Some(Type::Zero) => {} // This is a no-op since the partition is already zeroed
                        Some(op) => panic!("unimplemented operation: {op:?}"),
                        None => panic!("invalid op"),
                    };

                    progress.inc(1);
                });
            }
        }
        Ok(())
    })?;

    Ok(())
}

fn payload_mmap(path: impl AsRef<Path>) -> Result<Mmap> {
    let path = path.as_ref();
    let file =
        File::open(path).with_context(|| format!("unable to open file for reading: {path:?}"))?;
    unsafe { Mmap::map(&file) }.with_context(|| format!("failed to mmap file: {path:?}"))
}

fn partition_mmap(path: impl AsRef<Path>, len: u64) -> Result<MmapMut> {
    let path = path.as_ref();
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("unable to open file for writing: {path:?}"))?;
    file.set_len(len)?;
    unsafe { MmapMut::map_mut(&file) }.with_context(|| format!("failed to mmap file: {path:?}"))
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
            let start_block = extent
                .start_block
                .context("start_block not defined in extent")?
                as usize;
            let num_blocks = extent
                .num_blocks
                .context("num_blocks not defined in extent")? as usize;

            let partition_offset = start_block * block_size;
            let extent_len = num_blocks * block_size;

            ensure!(
                partition_offset + extent_len <= partition_len,
                "extent exceeds partition size"
            );
            let extent =
                unsafe { slice::from_raw_parts_mut(partition.add(partition_offset), extent_len) };

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
