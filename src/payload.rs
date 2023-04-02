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
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        const MAGIC_BYTES_LEN: usize = 4;
        const FILE_FORMAT_VERSION_LEN: usize = 8;
        const MANIFEST_SIZE_LEN: usize = 8;
        const METADATA_SIGNATURE_SIZE_LEN: usize = 4;

        let mut offset = 0;

        let magic_bytes = bytes
            .get(offset..offset + MAGIC_BYTES_LEN)
            .context("invalid file format")?;
        offset += MAGIC_BYTES_LEN;

        let file_format_version = {
            let bytes = bytes
                .get(offset..offset + FILE_FORMAT_VERSION_LEN)
                .context("invalid file format")?
                .try_into()
                .expect("incorrect size for file_format_version");
            offset += FILE_FORMAT_VERSION_LEN;
            u64::from_be_bytes(bytes)
        };

        let manifest_size = {
            let bytes = bytes
                .get(offset..offset + MANIFEST_SIZE_LEN)
                .context("invalid file format")?
                .try_into()
                .expect("incorrect size for manifest_size");
            offset += MANIFEST_SIZE_LEN;
            u64::from_be_bytes(bytes)
        };

        let metadata_signature_size = if file_format_version > 1 {
            let bytes = bytes
                .get(offset..offset + METADATA_SIGNATURE_SIZE_LEN)
                .context("invalid file format")?
                .try_into()
                .expect("incorrect size for metadata_signature");
            offset += METADATA_SIGNATURE_SIZE_LEN;
            Some(u32::from_be_bytes(bytes))
        } else {
            None
        };

        let manifest = bytes
            .get(offset..offset + manifest_size as usize)
            .context("invalid file format")?;
        offset += manifest_size as usize;

        let metadata_signature = match metadata_signature_size {
            Some(metadata_signature_size) => {
                let metadata_signature = bytes
                    .get(offset..offset + metadata_signature_size as usize)
                    .context("invalid file format")?;
                offset += metadata_signature_size as usize;
                Some(metadata_signature)
            }
            None => None,
        };

        let data = bytes.get(offset..).context("invalid file format")?;

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
}
