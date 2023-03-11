pub mod chromeos_update_engine {
    include!(concat!(env!("OUT_DIR"), "/chromeos_update_engine.rs"));
}

use crate::chromeos_update_engine::install_operation::Type;
use bzip2::bufread::BzDecoder;
use lzma::LzmaReader;
use prost::Message;
use std::convert::TryInto;
use std::fs::File;
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};

fn vm(op: chromeos_update_engine::InstallOperation, f: &mut File, d: &mut File, base_offset: u64) {
    const BLOCK_SIZE: u64 = 4096;
    f.seek(SeekFrom::Start(base_offset + op.data_offset.unwrap()))
        .unwrap();
    d.seek(SeekFrom::Start(
        op.dst_extents.first().unwrap().start_block.unwrap_or(0) * BLOCK_SIZE,
    ))
    .unwrap();

    let mut buf = vec![0; op.data_length.unwrap().try_into().unwrap()];
    f.read_exact(&mut buf).unwrap();
    let mut buf_d = Cursor::new(&mut buf);

    match Type::from_i32(op.r#type) {
        Some(Type::ReplaceXz) => {
            let mut decoder = LzmaReader::new_decompressor(&mut buf_d).unwrap();
            println!("OP::ReplaceXZ");
            io::copy(&mut decoder, d).unwrap();
        }
        Some(Type::ReplaceBz) => {
            println!("OP::ReplaceBz");
            let mut decoder = BzDecoder::new(&mut buf_d);
            io::copy(&mut decoder, d).unwrap();
        }
        Some(Type::Replace) => {
            println!("OP::Replace");
            io::copy(&mut buf_d, d).unwrap();
        }
        Some(Type::SourceCopy) => {
            unimplemented!("OP::SourceCopy")
        }
        Some(Type::Zero) => {
            println!("OP::Zero");
            d.write_all(&vec![
                0;
                (op.dst_extents
                    .first()
                    .unwrap()
                    .num_blocks
                    .unwrap_or(0)
                    * BLOCK_SIZE)
                    .try_into()
                    .unwrap()
            ])
            .unwrap();
        }
        None => println!("InvalidOP"),
        Some(_) => {
            unimplemented!("un-implemented OP")
        }
    }
}

fn dump_partition(part: chromeos_update_engine::PartitionUpdate, f: &mut File, offset: u64) {
    println!("Dumping partition: {}", part.partition_name);
    let mut partition_file = File::create(format!("{}.img", part.partition_name)).unwrap();
    for op in part.operations {
        vm(op, f, &mut partition_file, offset);
    }
}

fn main() {
    println!("Parsing payload");
    let mut f = File::open("/root/Documents/payload-dumper/test/payload.bin").unwrap();
    let mut offset = 0;

    // Read magic byte
    let mut buf = vec![0; 4];
    f.read_exact(&mut buf).unwrap();
    offset += 4;

    // Validate magic bytes
    assert_eq!(buf, "CrAU".as_bytes());

    // Read file format version
    let mut buf = vec![0; 8];
    f.read_exact(&mut buf).unwrap();
    offset += 8;
    let file_format_version = u64::from_be_bytes(buf.clone().try_into().unwrap());
    assert_eq!(file_format_version, 2);

    // Read metadata size
    f.read_exact(&mut buf).unwrap();
    offset += 8;
    let manifest_size = u64::from_be_bytes(buf.clone().try_into().unwrap());
    println!("Manifest size: {}", manifest_size);
    let metadata_signature_size = if file_format_version > 1 {
        f.read_exact(&mut buf[..4]).unwrap();
        offset += 4;
        u32::from_be_bytes(buf.clone()[..4].try_into().unwrap())
    } else {
        0
    };

    // Read metadata
    let mut manifest = vec![0; manifest_size.try_into().unwrap()];
    let mut metadata_signature = vec![0; metadata_signature_size.try_into().unwrap()];
    f.read_exact(&mut manifest).unwrap();
    offset += manifest_size;
    f.read_exact(&mut metadata_signature).unwrap();
    offset += metadata_signature_size as u64;

    let delta_archive_manifest =
        chromeos_update_engine::DeltaArchiveManifest::decode(manifest.as_slice()).unwrap();
    println!("block_size: {}", delta_archive_manifest.block_size.unwrap());
    for part in delta_archive_manifest.partitions {
        dump_partition(part, &mut f, offset);
    }
}
