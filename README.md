<!-- markdownlint-configure-file {
  "MD013": {
    "code_blocks": false,
    "tables": false
  },
  "MD033": false,
  "MD041": false
} -->

<div align="center">

# otadump

[![crates.io][crates.io-badge]][crates.io]
[![Downloads][downloads-badge]][releases]

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
# needs liblzma-dev
cargo install --locked otadump
```

### Windows

Download the pre-build binary from the [Releases] page. Extract it and run the
`otadump.exe` file.

## Usage

Run the following command in your terminal:

```sh
otadump payload.bin
```

[crates.io-badge]: https://img.shields.io/crates/v/otadump?logo=rust&logoColor=white&style=flat-square
[crates.io]: https://crates.io/crates/otadump
[downloads-badge]: https://img.shields.io/github/downloads/crazystylus/otadump/total?logo=github&logoColor=white&style=flat-square
[releases]: https://github.com/crazystylus/otadump/releases
