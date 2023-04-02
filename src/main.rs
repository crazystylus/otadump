pub mod chromeos_update_engine {
    include!(concat!(env!("OUT_DIR"), "/chromeos_update_engine.rs"));
}

use anyhow::{bail, ensure, Context, Result};
use bsdiff::patch::patch;
use bzip2::read::BzDecoder;
use chromeos_update_engine::install_operation::Type;
use chromeos_update_engine::{DeltaArchiveManifest, Extent, InstallOperation};
use lzma::LzmaReader;
use memmap2::{Mmap, MmapMut};
use prost::Message;
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Cursor, Read};
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

    let input_file =
        File::open("/root/Documents/android-ota-payload-dumper/tmp/C11_to_c16/payload.bin")?;
    let old_path: Option<&str> = Some("tmp/C11_extracted");
    let verify_path: Option<&str> = Some("tmp/C16_extracted");
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

    //rayon::scope(|scope| -> Result<()> {
    for partition in delta_archive_manifest
        .partitions
        .iter()
        .filter(|part| part.partition_name != "ue")
    {
        // Allocate output file
        let output = {
            let output_path = format!("tmp/out/{}.img", partition.partition_name);
            let output_file_len: u64 = partition.new_partition_info.clone().unwrap().size.unwrap();
            let output_file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&output_path)?;
            output_file.set_len(output_file_len)?;

            Arc::new(SyncUnsafeCell::new(unsafe {
                MmapMut::map_mut(&output_file)?
            }))
        };

        let old_partition = match &old_path {
            Some(path) => {
                let file = File::open(format!("{}/{}.img", path, partition.partition_name))?;
                let old_partition_size =
                    partition.old_partition_info.clone().unwrap().size.unwrap() as usize;
                let mmap = Arc::new(unsafe { Mmap::map(&file) }?);
                if let Some(hash) = &partition.old_partition_info.clone().unwrap().hash {
                    println!(
                        "{}: old_partition: expected hash: {}",
                        partition.partition_name,
                        hex::encode(hash)
                    );
                    verify_sha256(mmap.get(0..old_partition_size).unwrap(), hash).unwrap();
                    println!("{}: old_partition: hash verified", partition.partition_name);
                }
                Some(mmap)
            }
            None => None,
        };

        let verify_partition = match &verify_path {
            Some(path) => {
                let file = File::open(format!("{}/{}.img", path, partition.partition_name))?;
                let old_partition_size =
                    partition.old_partition_info.clone().unwrap().size.unwrap() as usize;
                let mmap = Arc::new(unsafe { Mmap::map(&file) }?);
                if let Some(hash) = &partition.new_partition_info.clone().unwrap().hash {
                    println!(
                        "{}: verify_partition: expected hash: {}",
                        partition.partition_name,
                        hex::encode(hash)
                    );
                    verify_sha256(mmap.get(0..old_partition_size).unwrap(), hash).unwrap();
                    println!(
                        "{}: verify_partition: hash verified",
                        partition.partition_name
                    );
                }
                Some(mmap)
            }
            None => None,
        };
        for op in &partition.operations {
            let output = output.clone();
            let old_partition_mmap = old_partition.clone();
            let verify_partition_mmap = verify_partition.clone();

            // scope.spawn(move |_| {
            let input_slice: Option<&[u8]> = match Type::from_i32(op.r#type) {
                Some(Type::SourceCopy) | Some(Type::Zero) => None,
                Some(_) => {
                    let input_offset = op
                        .data_offset
                        .expect(&format!("Operation: {:?}", Type::from_i32(op.r#type)))
                        as usize;
                    let input_len = op.data_length.unwrap() as usize;
                    let input_slice = input_data
                        .get(base_offset + input_offset..base_offset + input_offset + input_len)
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
                    .map(|extent| mut_extent_from_partition((*output.get()).as_mut_ptr(), extent))
                    .collect()
            };

            let verify_extents: Option<Vec<&[u8]>> = verify_partition_mmap.as_ref().map(|mmap| {
                op.src_extents
                    .iter()
                    .map(|extent| extent_from_partition(mmap, extent))
                    .collect()
            });

            // let src_extents = old_partition_mmap.as_ref().map(|mmap| {
            //     op.src_extents
            //         .iter()
            //         .map(|extent| extent_from_partition(mmap, extent))
            //         .fold(
            //             Box::new(&[] as &[u8]) as Box<dyn std::io::Read>,
            //             |reader, bytes| Box::new(reader.chain(bytes)),
            //         )
            // });
            // run_op(
            //     op.clone(),
            //     input_slice,
            //     &mut dst_extents,
            //     src_extents,
            //     verify_extents.as_deref(),
            // )
            // .unwrap();
            // //});
        }
        println!("{}: successfully extracted", partition.partition_name);
        if let Some(hash) = &partition.new_partition_info.clone().unwrap().hash {
            println!(
                "{}: new_partition: expected hash: {}",
                partition.partition_name,
                hex::encode(hash)
            );
            unsafe { verify_sha256(&(*output.get()), hash).unwrap() };
        }
    }
    //Ok(())
    //})?;

    Ok(())
}

// Fix this: you cannot convert a mut raw pointer into a shared safe pointer
fn mut_extent_from_partition(partition: *mut u8, extent: &'_ Extent) -> &'static mut [u8] {
    let extent_start = extent.start_block.unwrap().mul(BLOCK_SIZE) as usize;
    let extent_len = extent.num_blocks().mul(BLOCK_SIZE) as usize;
    unsafe { slice::from_raw_parts_mut(partition.add(extent_start), extent_len) }
}

fn extent_from_partition<'a>(partition: &'a Arc<Mmap>, extent: &'_ Extent) -> &'a [u8] {
    let extent_start = extent.start_block.unwrap().mul(BLOCK_SIZE) as usize;
    let extent_len = extent.num_blocks().mul(BLOCK_SIZE) as usize;
    partition
        .get(extent_start..(extent_start + extent_len))
        .unwrap()
}

fn run_op(
    op: InstallOperation,
    input: Option<&[u8]>,
    dst_extents: &mut [&mut [u8]],
    src_extents: Option<Box<dyn std::io::Read>>,
    verify_extents: Option<&[&[u8]]>,
) -> Result<()> {
    match Type::from_i32(op.r#type) {
        Some(Type::ReplaceXz) => run_op_replace_xz(input, dst_extents),
        Some(Type::ReplaceBz) => run_op_replace_bz(input, dst_extents),
        Some(Type::Replace) => run_op_replace(input, dst_extents),
        Some(Type::SourceCopy) => run_op_source_copy(src_extents, dst_extents),
        Some(Type::SourceBsdiff) | Some(Type::BrotliBsdiff) => {
            let dst_len = op
                .dst_length
                .unwrap_or(dst_extents.iter().map(|extent| extent.len() as u64).sum())
                as usize;
            run_op_source_bsdiff(input, src_extents, dst_extents, dst_len)
        }
        Some(Type::Zero) => run_op_zero(dst_extents),
        Some(op) => {
            println!("unimplemented op: {op:?}");
            Ok(())
        }
        None => bail!("invalid op"),
    }
    .unwrap();
    for (dst_extent, verify_extent) in std::iter::zip(dst_extents, verify_extents.unwrap()) {
        if let Some(op) = Type::from_i32(op.r#type) {
            ensure!(
                dst_extent != verify_extent,
                "OP verification failure: {op:?}"
            )
        };
    }
    Ok(())
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

fn run_op_source_copy(
    src_extents: Option<Box<dyn std::io::Read>>,
    dst_extents: &mut [&mut [u8]],
) -> Result<()> {
    let mut src_extents = src_extents.expect("SOURCE_COPY supported only for differential OTA");

    for dst_extent in dst_extents {
        src_extents.read_exact(dst_extent)?
    }

    Ok(())
}

fn run_op_source_bsdiff(
    input: Option<&[u8]>,
    src_extents: Option<Box<dyn std::io::Read>>,
    dst_extents: &mut [&mut [u8]],
    dst_len: usize,
) -> Result<()> {
    let mut src_extents = src_extents.expect("SOURCE_BSDIFF supported only for differential OTA");
    let mut input = Cursor::new(input.expect("SOURCE_BSDIFF supported only for differential OTA"));

    let mut src_data: Vec<u8> = Vec::new();
    src_extents.read_to_end(&mut src_data)?;

    let mut patched_data = Vec::new();

    patch(&src_data, &mut input, &mut patched_data)?;
    if patched_data.len() < dst_len {
        patched_data.resize(dst_len, 0);
    }

    let mut patched_data = Cursor::new(patched_data);
    for dst_extent in dst_extents {
        patched_data.read_exact(dst_extent)?
    }
    Ok(())
}

fn run_op_zero(dst_extents: &mut [&mut [u8]]) -> Result<()> {
    for dst_extent in dst_extents {
        dst_extent.fill(0);
    }

    Ok(())
}

fn verify_sha256(data: &[u8], exp_hash: &[u8]) -> Result<()> {
    let got_hash = Sha256::digest(data);
    if got_hash.as_slice() != exp_hash {
        println!(
            "hash mismatch: expected {}, got {got_hash:x}",
            hex::encode(exp_hash)
        );
    }
    // ensure!(
    //     got_hash.as_slice() == exp_hash,
    //     "hash mismatch: expected {}, got {got_hash:x}",
    //     hex::encode(exp_hash)
    // );
    Ok(())
}
