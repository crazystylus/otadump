<!-- markdownlint-configure-file {
  "MD033": false,
  "MD041": false
} -->

<div align="center">

# otadump

[![crates.io][crates.io-badge]][crates.io]

**`otadump` helps you extract partitions from Android OTA files.** <br />
Partitions can be individually flashed to your device using `fastboot`.

</div>

## Installation

### Linux / macOS

Install a pre-built binary:

```sh
curl -sS https://raw.githubusercontent.com/crazystylus/otadump/mainline/install.sh | bash
```

Otherwise, using Cargo:

```sh
# needs liblzma-dev and protobuf-compiler
cargo install --locked otadump
```

### Windows

Download the pre-built binary from the [Releases] page. Extract it and run the
`otadump.exe` file.

## Usage

Run the following command in your terminal:

```sh
otadump payload.bin
```

## Benchmarks

Comparing the time taken to extract all partitions from a few sample files
(lower is better):

![Benchmarks][benchmarks]

System specifications:

- Processor: AMD Ryzen 5 5600X (12) @ 3.700GHz
- RAM: 16 GiB
- OS: Pop!_OS 22.04 / Linux 6.0.6
- SSD: Samsung 970 EVO 250GB

[benchmarks]: contrib/benchmarks.svg
[crates.io-badge]: https://img.shields.io/crates/v/otadump?logo=rust&logoColor=white&style=flat-square
[crates.io]: https://crates.io/crates/otadump
[releases]: https://github.com/crazystylus/otadump/releases
