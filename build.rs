fn main() {
    prost_build::compile_protos(
        &["src/protos/chromeos_update_engine/update_metadata.proto"],
        &[] as &[&str],
    )
    .expect("error compiling protobuf files");
}
