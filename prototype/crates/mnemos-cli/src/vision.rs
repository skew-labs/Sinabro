//! [5] Multimodal / image input (B⑭) — local-vision-first. Threat model:
//! `ops/evidence/stage_g/agent_loop/VISION_THREAT_MODEL.md` (IV-VS1..IV-VS8).
//!
//! # Two capability-typed image paths
//!
//! * LOCAL describe (READ, free, NO egress): an image file becomes a READ context
//!   fragment — classified (magic-byte format + dimensions + sha), then DESCRIBED by a
//!   local vision model through the [`VisionPort`] seam. v1 ships a deterministic
//!   [`StubVision`] (a metadata summary — no model, no network), which makes the path
//!   hermetically testable AND honest today; a REAL local vision model drops into the
//!   SAME trait (the deferred quality live-fire). The image bytes NEVER leave the box on
//!   this path.
//! * FRONTIER image (EGRESS, owner-armed): sending the image to a frontier multimodal
//!   model. This is OWNER-ARMED ([`EgressCapability`] witness) and carries an EXPLICIT
//!   warning — **an image CANNOT be auto-redacted** (the `redact()` text wall cannot scan
//!   pixels; an image may embed secrets / faces / a screenshot of a key). The owner sees
//!   the warning before the image leaves the box.
//!
//! custody/funds/wallet/chain-write are HARD-LOCKED (PD-6): an image path touches none.

use crate::commands::authority::EgressCapability;

/// The owner-arm phrase for the frontier-image egress ceremony (the model cannot type it).
pub const VISION_FRONTIER_ARM_PHRASE: &str = "arm-frontier-image-egress-unredactable";

/// The hard image byte cap (a bounded read — never an unbounded slurp).
pub const IMAGE_MAX_BYTES: u64 = 8 * 1024 * 1024;

/// A recognized image format (detected by MAGIC BYTES, never the file extension).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageFormat {
    /// PNG (`\x89PNG\r\n\x1a\n`).
    Png,
    /// JPEG (`\xFF\xD8\xFF`).
    Jpeg,
    /// GIF (`GIF87a` / `GIF89a`).
    Gif,
    /// WebP (`RIFF....WEBP`).
    Webp,
}

impl ImageFormat {
    /// A stable lowercase label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Png => "png",
            Self::Jpeg => "jpeg",
            Self::Gif => "gif",
            Self::Webp => "webp",
        }
    }

    /// Detect the format from the leading magic bytes (fail-closed `None` — never the
    /// file extension, which a hostile name could spoof).
    #[must_use]
    pub fn from_magic(bytes: &[u8]) -> Option<Self> {
        if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
            Some(Self::Png)
        } else if bytes.starts_with(b"\xFF\xD8\xFF") {
            Some(Self::Jpeg)
        } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
            Some(Self::Gif)
        } else if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP" {
            Some(Self::Webp)
        } else {
            None
        }
    }
}

/// Why an image was rejected (fail-closed; explicit).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageDeny {
    /// The path was empty / whitespace.
    EmptyPath,
    /// The file could not be read (absent / permission / IO).
    Unreadable,
    /// The file exceeded [`IMAGE_MAX_BYTES`] (refused, never truncated).
    TooLarge,
    /// The bytes are not a recognized image (magic-byte mismatch).
    NotAnImage,
}

impl ImageDeny {
    /// A stable, secret-free class label.
    #[must_use]
    pub const fn class_label(self) -> &'static str {
        match self {
            Self::EmptyPath => "image.path.empty",
            Self::Unreadable => "image.file.unreadable",
            Self::TooLarge => "image.file.too_large",
            Self::NotAnImage => "image.file.not_an_image",
        }
    }
}

/// A classified image: metadata only (NO pixels) — the format, byte length, decoded
/// dimensions (when cheaply parseable from the header), and the content sha. This is what
/// surfaces; the raw bytes are held transiently by the caller for the vision describe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageFragment {
    /// The display path (as supplied).
    pub path: String,
    /// The magic-byte-detected format.
    pub format: ImageFormat,
    /// The byte length (≤ [`IMAGE_MAX_BYTES`]).
    pub bytes_len: u64,
    /// The pixel width, if cheaply parseable from the header (PNG / GIF); else 0.
    pub width: u32,
    /// The pixel height, if cheaply parseable from the header (PNG / GIF); else 0.
    pub height: u32,
    /// The SHA-256 (64-hex) of the image bytes.
    pub sha256_hex: String,
}

/// Parse `(width, height)` cheaply from the header for the formats that carry it in a
/// fixed location (PNG IHDR; GIF logical screen). JPEG / WebP need a real decoder ⇒
/// `(0, 0)` (honest "unknown without decode"). PURE, bounded reads.
fn header_dimensions(format: ImageFormat, bytes: &[u8]) -> (u32, u32) {
    match format {
        // PNG: IHDR width @ 16..20, height @ 20..24 (big-endian u32).
        ImageFormat::Png if bytes.len() >= 24 => {
            let w = u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
            let h = u32::from_be_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
            (w, h)
        }
        // GIF: logical screen width @ 6..8, height @ 8..10 (little-endian u16).
        ImageFormat::Gif if bytes.len() >= 10 => {
            let w = u32::from(u16::from_le_bytes([bytes[6], bytes[7]]));
            let h = u32::from(u16::from_le_bytes([bytes[8], bytes[9]]));
            (w, h)
        }
        _ => (0, 0),
    }
}

/// Classify image bytes (PURE, no IO): detect the format by magic, parse cheap dimensions,
/// hash. Fail-closed [`ImageDeny::NotAnImage`] on a magic-byte mismatch.
pub fn classify_image_bytes(path: &str, bytes: &[u8]) -> Result<ImageFragment, ImageDeny> {
    let format = ImageFormat::from_magic(bytes).ok_or(ImageDeny::NotAnImage)?;
    let (width, height) = header_dimensions(format, bytes);
    Ok(ImageFragment {
        path: path.chars().take(200).collect(),
        format,
        bytes_len: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        width,
        height,
        sha256_hex: crate::hex32(&crate::sha256_32(bytes)),
    })
}

/// Read + classify an image file (bounded by [`IMAGE_MAX_BYTES`]). Returns the fragment
/// (metadata) + the raw bytes (held transiently for the vision describe; NEVER stored).
/// Fail-closed on empty path / unreadable / over-cap / not-an-image.
pub fn classify_image_file(path: &str) -> Result<(ImageFragment, Vec<u8>), ImageDeny> {
    use std::io::Read;
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err(ImageDeny::EmptyPath);
    }
    let file = std::fs::File::open(trimmed).map_err(|_| ImageDeny::Unreadable)?;
    // Bounded read: at most cap+1; MORE than the cap ⇒ refuse (never truncate-as-truth).
    let mut buf = Vec::new();
    let mut limited = file.take(IMAGE_MAX_BYTES.saturating_add(1));
    limited
        .read_to_end(&mut buf)
        .map_err(|_| ImageDeny::Unreadable)?;
    if u64::try_from(buf.len()).unwrap_or(u64::MAX) > IMAGE_MAX_BYTES {
        return Err(ImageDeny::TooLarge);
    }
    let fragment = classify_image_bytes(trimmed, &buf)?;
    Ok((fragment, buf))
}

/// The pluggable LOCAL vision seam. v1 = [`StubVision`] (deterministic metadata describe,
/// NO model / NO network); a real local vision model implements the SAME trait (the
/// deferred live-fire). The describe runs LOCAL — the image bytes never leave the box.
pub trait VisionPort {
    /// Describe the image LOCALLY. Returns a secret-free description (or `None` if the
    /// model is unavailable — honest-degrade, never a fabricated description).
    fn describe(&self, fragment: &ImageFragment, bytes: &[u8]) -> Option<String>;
}

/// The deterministic, model-free local describer: a metadata summary (format, dimensions,
/// size, sha). NOT a content description — but honest, deterministic (hermetic tests), and
/// useful today; a real local vision model swaps in at the [`VisionPort`] seam to describe
/// the actual content.
#[derive(Debug, Default, Clone, Copy)]
pub struct StubVision;

impl VisionPort for StubVision {
    fn describe(&self, fragment: &ImageFragment, _bytes: &[u8]) -> Option<String> {
        let dims = if fragment.width > 0 && fragment.height > 0 {
            format!("{}x{}", fragment.width, fragment.height)
        } else {
            "dimensions need a decoder".to_string()
        };
        Some(format!(
            "a {} image ({}, {} bytes); local-vision metadata describe — wire a real local \
             vision model at the seam for content understanding",
            fragment.format.label(),
            dims,
            fragment.bytes_len
        ))
    }
}

/// The rendered outcome of an image READ (local): a secret-free fragment line + the local
/// description, plus the K-budget `consumed_read` flag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageRender {
    /// The rendered, secret-free result string (metadata + local description).
    pub rendered: String,
    /// Whether the image was admitted + described (a deny consumes no K).
    pub consumed_read: bool,
    /// A stable, secret-free class label.
    pub class_label: &'static str,
}

/// The LOCAL image-as-READ-context pipeline (IV-VS1..IV-VS4): read + classify the image,
/// describe it LOCALLY (no egress), and render a context fragment. The image bytes never
/// leave the box. A deny / no-describe consumes no K.
#[must_use]
pub fn render_image_context(port: &dyn VisionPort, path: &str) -> ImageRender {
    let (fragment, bytes) = match classify_image_file(path) {
        Ok(ok) => ok,
        Err(deny) => {
            return ImageRender {
                rendered: format!(
                    "image denied ({}): {}",
                    deny.class_label(),
                    path.chars().take(120).collect::<String>()
                ),
                consumed_read: false,
                class_label: deny.class_label(),
            };
        }
    };
    let Some(description) = port.describe(&fragment, &bytes) else {
        return ImageRender {
            rendered: format!(
                "image {} ({}): no local vision model wired (honest-degrade)",
                fragment.path,
                fragment.format.label()
            ),
            consumed_read: false,
            class_label: "image.vision.not_wired",
        };
    };
    let dims = if fragment.width > 0 && fragment.height > 0 {
        format!("{}x{}", fragment.width, fragment.height)
    } else {
        "?x?".to_string()
    };
    let rendered = format!(
        "image {path} (local READ; no egress)\n\
         format={fmt} dims={dims} bytes={bytes} sha256={sha}\n\
         describe: {desc}",
        path = fragment.path,
        fmt = fragment.format.label(),
        dims = dims,
        bytes = fragment.bytes_len,
        sha = fragment.sha256_hex,
        desc = description,
    );
    ImageRender {
        rendered,
        consumed_read: true,
        class_label: "image.local.described",
    }
}

/// A minimal base64 (standard alphabet, padded) encoder — for the frontier-image data
/// URL. No external crate; deterministic.
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(ALPHABET[(b0 >> 2) as usize] as char);
        out.push(ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(b2 & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// The rendered outcome of a frontier-image PREPARE: the unredactable warning + the
/// egress-ready data-URL metadata + a stable label + an `armed_ok` flag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrontierImageRender {
    /// The rendered, secret-free result string (the warning + the prepared metadata).
    pub rendered: String,
    /// A stable, secret-free class label.
    pub class_label: &'static str,
    /// Whether the image was classified + prepared for egress (a deny is `false`).
    pub prepared: bool,
}

/// The FRONTIER-IMAGE egress PREPARE (IV-VS5..IV-VS8). REQUIRES an [`EgressCapability`]
/// witness (owner-armed — the model holds no constructor, so it cannot self-send an
/// image). Classifies the image, then renders the EXPLICIT **cannot-be-auto-redacted**
/// warning + the egress-ready `data:` URL metadata (a base64 data URL is built — the
/// plumbing is complete). The ACTUAL frontier multimodal SEND is the deferred live-fire
/// (the live consult body is text-only; a real multimodal frontier API is owner go-live).
/// The owner sees the warning BEFORE any image leaves the box.
#[must_use]
pub fn render_frontier_image(_cap: &EgressCapability, path: &str) -> FrontierImageRender {
    let (fragment, bytes) = match classify_image_file(path) {
        Ok(ok) => ok,
        Err(deny) => {
            return FrontierImageRender {
                rendered: format!("frontier image denied ({})", deny.class_label()),
                class_label: deny.class_label(),
                prepared: false,
            };
        }
    };
    // Build the egress-ready data URL (plumbing complete) — but surface only its LENGTH,
    // never the base64 body (it would bloat the render; the real send carries it).
    let data_url_prefix = format!("data:image/{};base64,", fragment.format.label());
    let b64 = base64_encode(&bytes);
    let data_url_len = data_url_prefix.len() + b64.len();
    let rendered = format!(
        "frontier image PREPARED (owner-armed EGRESS) — {path}\n\
         ⚠ WARNING: an image CANNOT be auto-redacted — the redact() text wall cannot scan \
         pixels. This image ({fmt}, {bytes} bytes, sha {sha}) may embed secrets, faces, or a \
         screenshot of a key. It will leave the box UN-redacted to the frontier. Proceed ONLY \
         if you intend the frontier to see exactly these pixels.\n\
         egress-ready: {prefix}<{len}-byte base64 data URL> (the real multimodal send is the \
         deferred owner go-live; the live consult body is text-only today)",
        path = fragment.path,
        fmt = fragment.format.label(),
        bytes = fragment.bytes_len,
        sha = fragment.sha256_hex,
        prefix = data_url_prefix,
        len = data_url_len,
    );
    FrontierImageRender {
        rendered,
        class_label: "image.frontier.prepared_warned",
        prepared: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // a 1x1 PNG (valid magic + IHDR), tiny.
    fn tiny_png() -> Vec<u8> {
        let mut v = vec![0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n'];
        v.extend_from_slice(&[0, 0, 0, 0x0d]); // IHDR length
        v.extend_from_slice(b"IHDR");
        v.extend_from_slice(&1u32.to_be_bytes()); // width 1
        v.extend_from_slice(&1u32.to_be_bytes()); // height 1
        v.extend_from_slice(&[8, 6, 0, 0, 0]); // bit depth / color / etc.
        v.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // (fake) crc
        v
    }

    #[test]
    fn magic_detects_format_not_extension() {
        assert_eq!(ImageFormat::from_magic(&tiny_png()), Some(ImageFormat::Png));
        assert_eq!(
            ImageFormat::from_magic(b"\xFF\xD8\xFF\xE0junk"),
            Some(ImageFormat::Jpeg)
        );
        assert_eq!(
            ImageFormat::from_magic(b"GIF89a..."),
            Some(ImageFormat::Gif)
        );
        assert_eq!(
            ImageFormat::from_magic(b"RIFF\x00\x00\x00\x00WEBPxx"),
            Some(ImageFormat::Webp)
        );
        // a text file (or a renamed .png that is really text) is NOT an image.
        assert_eq!(ImageFormat::from_magic(b"not an image at all"), None);
    }

    #[test]
    fn classify_bytes_parses_png_dimensions_and_hashes() {
        let frag = classify_image_bytes("a.png", &tiny_png()).expect("png");
        assert_eq!(frag.format, ImageFormat::Png);
        assert_eq!(frag.width, 1);
        assert_eq!(frag.height, 1);
        assert_eq!(frag.sha256_hex.len(), 64);
        // a non-image is fail-closed.
        assert_eq!(
            classify_image_bytes("x.txt", b"hello world this is text").unwrap_err(),
            ImageDeny::NotAnImage
        );
    }

    #[test]
    fn stub_vision_describes_locally_and_render_is_read_no_egress() {
        let frag = classify_image_bytes("a.png", &tiny_png()).expect("png");
        let desc = StubVision.describe(&frag, &tiny_png()).expect("describe");
        assert!(desc.contains("png"));
        assert!(desc.contains("1x1"));
        // the render is a local READ — it must say so + never claim egress.
        // (render_image_context reads a file; exercised via classify here + the LIVE smoke.)
        assert!(desc.contains("local-vision"));
    }

    #[test]
    fn frontier_image_prepare_warns_unredactable() {
        let cap = crate::commands::authority::test_egress_capability();
        // write a tiny png to a temp file so the file-read path runs.
        let dir = std::env::temp_dir().join(format!("sinabro-vision-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("t.png");
        std::fs::write(&path, tiny_png()).expect("write");
        let render = render_frontier_image(&cap, &path.to_string_lossy());
        assert!(render.prepared, "{}", render.rendered);
        assert_eq!(render.class_label, "image.frontier.prepared_warned");
        // the unredactable warning MUST be present (the load-bearing gate).
        assert!(render.rendered.contains("CANNOT be auto-redacted"));
        assert!(render.rendered.contains("data:image/png;base64,"));
        // the base64 body itself is NOT dumped (only its length).
        assert!(render.rendered.contains("base64 data URL"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn local_render_denies_a_non_image_path_without_consuming_k() {
        let dir = std::env::temp_dir().join(format!("sinabro-vision-test2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("t.txt");
        std::fs::write(&path, b"definitely not an image, just prose").expect("write");
        let r = render_image_context(&StubVision, &path.to_string_lossy());
        assert!(!r.consumed_read);
        assert_eq!(r.class_label, "image.file.not_an_image");
        // an empty path is fail-closed too.
        assert_eq!(
            render_image_context(&StubVision, "   ").class_label,
            "image.path.empty"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn class_labels_are_stable() {
        assert_eq!(
            ImageDeny::NotAnImage.class_label(),
            "image.file.not_an_image"
        );
        assert_eq!(ImageDeny::TooLarge.class_label(), "image.file.too_large");
    }
}
