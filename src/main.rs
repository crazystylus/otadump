use payload_dumper::chromeos_update_engine::DeltaArchiveManifest;
use payload_dumper::dump_partition;
use prost::Message;
use std::convert::TryInto;
use std::fs::File;
use std::io::Read;

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

    let delta_archive_manifest = DeltaArchiveManifest::decode(manifest.as_slice()).unwrap();
    println!("block_size: {}", delta_archive_manifest.block_size.unwrap());
    for part in delta_archive_manifest.partitions {
        dump_partition(part, &mut f, offset);
    }
}
