use std::mem;

use anyhow::{Context, Result};

/// Update file format: contains all the operations needed to update a system to
/// a specific version. It can be a full payload which can update from any
/// version, or a delta payload which can only update from a specific version.
pub struct Payload<'a> {
    /// Should be "CrAU"
    pub magic_bytes: &'a [u8],
    /// Payload major version
    pub file_format_version: u64,
    /// Size of protobuf [`DeltaArchiveManifest`]
    pub manifest_size: u64,
    /// Only present if format_version >= 2
    pub metadata_signature_size: Option<u32>,
    // The DeltaArchiveManifest protobuf serialized, not compressed.
    pub manifest: &'a [u8],
    // The signature of the metadata (from the beginning of the payload up to
    // this location, not including the signature itself). This is a serialized
    // Signatures message.
    pub metadata_signature: Option<&'a [u8]>,
    // Data blobs for files, no specific format. The specific offset
    // and length of each data blob is recorded in the DeltaArchiveManifest.
    pub data: &'a [u8],
}

impl<'a> Payload<'a> {
    // FIXME: use nom-derive for parsing once issue is resolved:
    // https://github.com/rust-bakery/nom-derive/issues/58
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        let (magic_bytes, offset) =
            Self::get_bytes(bytes, 0, 4).context("invalid file format: magic_bytes not found")?;

        let (file_format_version, offset) = Self::get_u64(bytes, offset)
            .context("invalid file format: file_format_version not found")?;

        let (manifest_size, offset) =
            Self::get_u64(bytes, offset).context("invalid file format: manifest_size not found")?;

        let (metadata_signature_size, offset) = if file_format_version > 1 {
            let (value, offset) = Self::get_u32(bytes, offset)
                .context("invalid file format: manifest_size not found")?;
            (Some(value), offset)
        } else {
            (None, offset)
        };

        let (manifest, offset) = Self::get_bytes(bytes, offset, manifest_size as usize)
            .context("invalid file format: manifest not found")?;

        let (metadata_signature, offset) = match metadata_signature_size {
            Some(len) => {
                let (value, offset) = Self::get_bytes(bytes, offset, len as usize)
                    .context("invalid file format: metadata_signature not found")?;
                (Some(value), offset)
            }
            None => (None, offset),
        };

        let data = bytes.get(offset..).context("invalid file format: data not found")?;

        let payload = Self {
            magic_bytes,
            file_format_version,
            manifest_size,
            metadata_signature_size,
            manifest,
            metadata_signature,
            data,
        };
        Ok(payload)
    }

    fn get_bytes(bytes: &[u8], offset: usize, len: usize) -> Option<(&[u8], usize)> {
        let bytes = bytes.get(offset..offset + len)?;
        Some((bytes, offset + len))
    }

    fn get_u64(bytes: &[u8], offset: usize) -> Option<(u64, usize)> {
        const LEN: usize = mem::size_of::<u64>();
        let bytes = bytes.get(offset..offset + LEN)?.try_into().expect("wrong slice length");
        Some((u64::from_be_bytes(bytes), offset + LEN))
    }

    fn get_u32(bytes: &[u8], offset: usize) -> Option<(u32, usize)> {
        const LEN: usize = mem::size_of::<u32>();
        let bytes = bytes.get(offset..offset + LEN)?.try_into().expect("wrong slice length");
        Some((u32::from_be_bytes(bytes), offset + LEN))
    }
}
