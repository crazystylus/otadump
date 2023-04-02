pub mod chromeos_update_engine {
    include!(concat!(env!("OUT_DIR"), "/chromeos_update_engine.rs"));
}

use anyhow::{bail, ensure, Context, Result};
use bzip2::read::BzDecoder;
use chromeos_update_engine::install_operation::Type;
use chromeos_update_engine::{DeltaArchiveManifest, Extent, InstallOperation};
use lzma::LzmaReader;
use memmap2::{Mmap, MmapMut};
use prost::Message;
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::ops::Mul;
use std::slice;
use std::sync::Arc;
use sync_unsafe_cell::SyncUnsafeCell;

const BLOCK_SIZE: u64 = 4096;

pub fn main() -> Result<()> {
    const MAGIC_BYTES_LEN: usize = 4;
    const FILE_FORMAT_VERSION_LEN: usize = 8;
    const MANIFEST_SIZE_LEN: usize = 8;
    const METADATA_SIGNATURE_SIZE_LEN: usize = 4;

    let input_file = File::open("/Users/ajeetdsouza/ws/payload-dumper/payload.bin")?;
    let input_mmap = unsafe { Mmap::map(&input_file) }?;
    let input_data = input_mmap.as_ref();
    let mut base_offset = 0;

    // Read and validate magic bytes
    if input_data.get(base_offset..base_offset + MAGIC_BYTES_LEN) != Some(b"CrAU") {
        bail!("invalid magic bytes");
    }
    base_offset += MAGIC_BYTES_LEN;

    // Read and validate version
    let file_format_version = {
        let bytes = input_data
            .get(base_offset..base_offset + FILE_FORMAT_VERSION_LEN)
            .context("invalid file format")?;
        base_offset += FILE_FORMAT_VERSION_LEN;
        u64::from_be_bytes(
            bytes
                .try_into()
                .expect("incorrect size for file_format_version"),
        )
    };
    if file_format_version != 2 {
        bail!("unsupported version: {}", file_format_version);
    }

    // Read manifest size
    let manifest_size: usize = {
        let bytes = input_data
            .get(base_offset..base_offset + MANIFEST_SIZE_LEN)
            .context("invalid file format")?;
        base_offset += MANIFEST_SIZE_LEN;
        u64::from_be_bytes(bytes.try_into().expect("incorrect size for manifest_size"))
            .try_into()?
    };

    // Read metadata signature size
    let metadata_signature_size = if file_format_version > 1 {
        let bytes = input_data
            .get(base_offset..base_offset + METADATA_SIGNATURE_SIZE_LEN)
            .context("invalid file format")?;
        base_offset += METADATA_SIGNATURE_SIZE_LEN;
        u32::from_be_bytes(
            bytes
                .try_into()
                .expect("incorrect size for metadata_signature"),
        )
        .try_into()?
    } else {
        0
    };

    // Read manifest
    let manifest = input_data
        .get(base_offset..base_offset + manifest_size)
        .context("invalid file format")?;
    base_offset += manifest_size;

    // Read metadata signature
    let _metadata_signature = input_data
        .get(base_offset..base_offset + metadata_signature_size)
        .context("invalid file format")?;
    base_offset += metadata_signature_size;

    // Decode manifest
    let delta_archive_manifest =
        DeltaArchiveManifest::decode(manifest).context("failed to decode file")?;

    rayon::scope(|scope| -> Result<()> {
        for partition in delta_archive_manifest.partitions {
            const BLOCK_SIZE: u64 = 4096;

            // Allocate output file
            let output_path = format!("tmp/{}.img", partition.partition_name);
            let output_file_len: u64 = partition.new_partition_info.unwrap().size.unwrap();
            let output_file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&output_path)?;
            output_file.set_len(output_file_len)?;

            let output = Arc::new(SyncUnsafeCell::new(unsafe {
                MmapMut::map_mut(&output_file)
            }?));

            for op in partition.operations {
                let output = Arc::clone(&output);
                scope.spawn(move |_| {
                    let input_slice: Option<&[u8]> = match Type::from_i32(op.r#type) {
                        Some(Type::SourceCopy) | Some(Type::Zero) => None,
                        Some(_) => {
                            let input_offset = op
                                .data_offset
                                .expect(&format!("Operation: {:?}", Type::from_i32(op.r#type)))
                                as usize;
                            let input_len = op.data_length.unwrap() as usize;
                            let input_slice = input_data
                                .get(
                                    base_offset + input_offset
                                        ..base_offset + input_offset + input_len,
                                )
                                .unwrap();
                            if let Some(hash) = &op.data_sha256_hash {
                                verify_sha256(input_slice, hash).unwrap();
                            }
                            Some(input_slice)
                        }
                        None => None,
                    };

                    let mut dst_extents: Vec<&mut [u8]> = unsafe {
                        op.dst_extents
                            .iter()
                            .map(|extent| {
                                mut_extent_from_partition((*output.get()).as_mut_ptr(), extent)
                            })
                            .collect()
                    };

                    run_op(op, input_slice, &mut dst_extents).unwrap();
                });
            }
        }
        Ok(())
    })?;

    Ok(())
}

// TODO: (bug) you cannot convert a mut raw pointer into a shared safe pointer
fn mut_extent_from_partition(partition: *mut u8, extent: &'_ Extent) -> &'static mut [u8] {
    let extent_start = extent.start_block.unwrap().mul(BLOCK_SIZE) as usize;
    let extent_len = extent.num_blocks().mul(BLOCK_SIZE) as usize;
    unsafe { slice::from_raw_parts_mut(partition.add(extent_start), extent_len) }
}

fn run_op(op: InstallOperation, input: Option<&[u8]>, dst_extents: &mut [&mut [u8]]) -> Result<()> {
    match Type::from_i32(op.r#type) {
        Some(Type::ReplaceXz) => run_op_replace_xz(input, dst_extents),
        Some(Type::ReplaceBz) => run_op_replace_bz(input, dst_extents),
        Some(Type::Replace) => run_op_replace(input, dst_extents),
        Some(Type::Zero) => Ok(()), // NO OP, new partition is already zeroed
        Some(op) => bail!("unimplemented op: {op:?}"),
        None => bail!("invalid op"),
    }
}

fn run_op_replace_xz(input: Option<&[u8]>, output: &mut [&mut [u8]]) -> Result<()> {
    ensure!(
        output.len() == 1,
        "invalid dst_extents for the operation: REPLACE_XZ"
    );
    let output = output.first_mut().unwrap();
    let input = input.unwrap();
    let mut decoder = LzmaReader::new_decompressor(input).unwrap();
    decoder
        .read_exact(output)
        .context("failed to decompress xz stream")?;
    ensure!(decoder.bytes().next().is_none(), "extra bytes in xz stream");
    Ok(())
}

fn run_op_replace_bz(input: Option<&[u8]>, output: &mut [&mut [u8]]) -> Result<()> {
    ensure!(output.len() == 1, "invalid dst_extents");
    let output = output.first_mut().unwrap();
    let input = input.unwrap();
    let mut decoder = BzDecoder::new(input);
    decoder
        .read_exact(output)
        .context("failed to decompress bz stream")?;
    ensure!(decoder.bytes().next().is_none(), "extra bytes in bz stream");
    Ok(())
}

fn run_op_replace(input: Option<&[u8]>, output: &mut [&mut [u8]]) -> Result<()> {
    ensure!(
        output.len() == 1,
        "invalid dst_extents for the operation: REPLACE"
    );
    let output = output.first_mut().unwrap();
    let input = input.unwrap();
    ensure!(
        input.len() == output.len(),
        "size mismatch for replace block"
    );
    output.copy_from_slice(input);
    Ok(())
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
