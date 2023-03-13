pub mod chromeos_update_engine {
    include!(concat!(env!("OUT_DIR"), "/chromeos_update_engine.rs"));
}

use anyhow::{bail, Context, Result};
use bzip2::read::BzDecoder;
use chromeos_update_engine::install_operation::Type;
use chromeos_update_engine::{DeltaArchiveManifest, InstallOperation};
use lzma::LzmaReader;
use memmap2::{Mmap, MmapMut};
use prost::Message;
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::ops::Range;
use std::slice;
use std::sync::Arc;
use sync_unsafe_cell::SyncUnsafeCell;

pub fn main() -> Result<()> {
    let input_file = File::open("/Users/ajeetdsouza/ws/payload-dumper/payload.bin")?;
    let input = unsafe { Mmap::map(&input_file) }?;

    const MAGIC_BYTES_IDX: Range<usize> = 0..4;
    const FILE_FORMAT_VERSION_IDX: Range<usize> = 4..12;
    const MANIFEST_SIZE_IDX: Range<usize> = 12..20;
    const METADATA_SIGNATURE_SIZE_IDX: Range<usize> = 20..24;

    // Validate magic bytes
    if input.get(MAGIC_BYTES_IDX) != Some(b"CrAU") {
        bail!("invalid magic bytes");
    }

    // Extract and validate version
    let file_format_version = {
        let bytes = input
            .get(FILE_FORMAT_VERSION_IDX)
            .context("invalid file format")?;
        u64::from_be_bytes(bytes.try_into().expect(""))
    };
    if file_format_version != 2 {
        bail!("unsupported version: {}", file_format_version);
    }

    // Read manifest size
    let manifest_size: usize = {
        let bytes = input
            .get(MANIFEST_SIZE_IDX)
            .context("invalid file format")?;
        u64::from_be_bytes(bytes.try_into().expect("")).try_into()?
    };

    // Read metadata signature size
    let metadata_signature_size = if file_format_version > 1 {
        let bytes = input
            .get(METADATA_SIGNATURE_SIZE_IDX)
            .context("invalid file format")?;
        u32::from_be_bytes(bytes.try_into().unwrap()).try_into()?
    } else {
        0
    };

    // Read manifest
    // TODO: we're not handling the file format version 1 case here
    let mut offset = METADATA_SIGNATURE_SIZE_IDX.end;
    let manifest = input
        .get(offset..offset + manifest_size)
        .context("invalid file format")?;
    offset += manifest_size;

    // Read metadata signature
    let _metadata_signature = input
        .get(offset..offset + metadata_signature_size)
        .context("invalid file format")?;
    offset += metadata_signature_size;

    let input = input.get(offset..).unwrap();

    // Decode manifest
    let delta_archive_manifest = DeltaArchiveManifest::decode(manifest)?;

    rayon::scope(|scope| -> Result<()> {
        for partition in delta_archive_manifest.partitions {
            const BLOCK_SIZE: u64 = 4096;

            let output_len: u64 = partition
                .operations
                .iter()
                .map(|op| op.dst_extents.first().unwrap().num_blocks() * BLOCK_SIZE)
                .sum();
            let output_path = format!("tmp/{}.img", partition.partition_name);

            dbg!(&output_path);
            let output_file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&output_path)?;
            output_file.set_len(output_len)?;

            let output = Arc::new(SyncUnsafeCell::new(unsafe {
                MmapMut::map_mut(&output_file)
            }?));

            for op in partition.operations {
                let output = Arc::clone(&output);
                scope.spawn(move |_| {
                    let input_offset = op.data_offset.unwrap().try_into().unwrap();
                    let input_len: usize = op.data_length.unwrap().try_into().unwrap();
                    let input_data = input.get(input_offset..input_offset + input_len).unwrap();

                    let output_offset = (op.dst_extents.first().unwrap().start_block.unwrap_or(0)
                        * BLOCK_SIZE)
                        .try_into()
                        .unwrap();
                    let output_len = (op.dst_extents.first().unwrap().num_blocks() * BLOCK_SIZE)
                        .try_into()
                        .unwrap();
                    let output_data = unsafe {
                        slice::from_raw_parts_mut(
                            (*output.get()).as_mut_ptr().add(output_offset),
                            output_len,
                        )
                    };

                    if let Some(hash) = &op.data_sha256_hash {
                        verify_sha256(input_data, hash);
                    }

                    run_op(op, input_data, output_data);
                });
            }
        }
        Ok(())
    })?;

    Ok(())
}

fn run_op(op: InstallOperation, input: &[u8], output: &mut [u8]) {
    match Type::from_i32(op.r#type) {
        Some(Type::ReplaceXz) => run_op_replace_xz(input, output),
        Some(Type::ReplaceBz) => run_op_replace_bz(input, output),
        Some(Type::Replace) => run_op_replace(input, output),
        Some(op) => unimplemented!("unimplemented op: {op:?}"),
        None => panic!("invalid op"),
    }
}

fn run_op_replace_xz(input: &[u8], output: &mut [u8]) {
    let mut decoder = LzmaReader::new_decompressor(input).unwrap();
    decoder.read_exact(output).unwrap();
    assert!(decoder.bytes().next().is_none(), "extra bytes in xz stream");
}

fn run_op_replace_bz(input: &[u8], output: &mut [u8]) {
    let mut decoder = BzDecoder::new(input);
    decoder.read_exact(output).unwrap();
    assert!(decoder.bytes().next().is_none(), "extra bytes in bz stream");
}

fn run_op_replace(input: &[u8], output: &mut [u8]) {
    output.copy_from_slice(input);
}

fn verify_sha256(data: &[u8], exp_hash: &[u8]) {
    let got_hash = Sha256::digest(data);
    if got_hash.as_slice() != exp_hash {
        panic!(
            "hash mismatch: expected {}, got {got_hash:x}",
            hex::encode(exp_hash)
        );
    }
}
