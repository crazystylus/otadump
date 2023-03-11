extern crate prost_build;

fn main() {
    prost_build::compile_protos(
        &["src/chromeos_update_engine/update_metadata.proto"],
        &["src/chromeos_update_engine/"],
    )
    .unwrap();
}
