use anyhow::{anyhow, Result};
use nom_derive::{NomBE, Parse};

/// Update file format: contains all the operations needed to update a system to
/// a specific version. It can be a full payload which can update from any
/// version, or a delta payload which can only update from a specific version.
#[derive(Debug, NomBE)]
pub struct Payload<'a> {
    /// Should be "CrAU".
    #[nom(Tag = r#"b"CrAU""#)]
    pub magic_bytes: &'a [u8],

    /// Payload major version.
    pub file_format_version: u64,

    /// Size of [`DeltaArchiveManifest`].
    pub manifest_size: u64,

    /// Only present if format_version >= 2.
    #[nom(If = "file_format_version > 1")]
    pub metadata_signature_size: Option<u32>,

    /// This is a serialized [`DeltaArchiveManifest`] message.
    #[nom(Take = "manifest_size")]
    pub manifest: &'a [u8],

    /// The signature of the metadata (from the beginning of the payload up to
    /// this location, not including the signature itself). This is a serialized
    /// [`Signatures`] message.
    #[nom(If = "metadata_signature_size.is_some()", Take = "metadata_signature_size.unwrap()")]
    pub metadata_signature: Option<&'a [u8]>,

    /// Data blobs for files, no specific format. The specific offset and length
    /// of each data blob is recorded in the [`DeltaArchiveManifest`].
    #[nom(Parse = "::nom::combinator::rest")]
    pub data: &'a [u8],
}

impl<'a> Payload<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        // TODO: this outputs the entire bytes of the file in the event of a
        // parser error. Use nom's VerboseError here.
        let (_, payload): (_, Payload) = Parse::parse(bytes)
            .map_err(|e| anyhow!(e.to_string()).context("failed to parse payload"))?;
        Ok(payload)
    }
}
