pub mod chromeos_update_engine {
    include!(concat!(env!("OUT_DIR"), "/chromeos_update_engine.rs"));
}

use crate::chromeos_update_engine::install_operation::Type;
use bzip2::bufread::BzDecoder;
use lzma::LzmaReader;
use std::convert::TryInto;
use std::fs::File;
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};

pub fn vm(
    op: chromeos_update_engine::InstallOperation,
    f: &mut File,
    d: &mut File,
    base_offset: u64,
) {
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

pub fn dump_partition(part: chromeos_update_engine::PartitionUpdate, f: &mut File, offset: u64) {
    println!("Dumping partition: {}", part.partition_name);
    let mut partition_file = File::create(format!("{}.img", part.partition_name)).unwrap();
    for op in part.operations {
        vm(op, f, &mut partition_file, offset);
    }
}
