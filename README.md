<!-- markdownlint-configure-file {
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

## Benchmarks

Comparing the time taken to extract all partitions from a few sample files
(lower is better):

|                           | [SD2A.220601.003] (`bluejay`) | ColorOS 13 F.13 (`instantnoodlep`) |
| ------------------------- | ----------------------------: | ---------------------------------: |
| **[crazystylus/otadump]** |                  **00:00:08** |                       **00:00:21** |
| [ssut/payload-dumper-go]  |                      00:00:40 |                           00:00:44 |
| [vm03/payload_dumper]     |    [Failed][extraction-issue] |                           00:00:59 |

[crates.io-badge]: https://img.shields.io/crates/v/otadump?logo=rust&logoColor=white&style=flat-square
[crates.io]: https://crates.io/crates/otadump
[crazystylus/otadump]: https://github.com/crazystylus/otadump
[downloads-badge]: https://img.shields.io/github/downloads/crazystylus/otadump/total?logo=github&logoColor=white&style=flat-square
[extraction-issue]: https://github.com/vm03/payload_dumper/issues/52
[releases]: https://github.com/crazystylus/otadump/releases
[sd2a.220601.003]: https://dl.google.com/dl/android/aosp/bluejay-ota-sd2a.220601.003-ddfde1f7.zip
[ssut/payload-dumper-go]: https://github.com/ssut/payload-dumper-go
[vm03/payload_dumper]: https://github.com/vm03/payload_dumper
