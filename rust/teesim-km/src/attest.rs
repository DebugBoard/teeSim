// Attestation signing keys loaded from a keybox.xml.
//
// Implements the TA's `RetrieveCertSigningInfo` trait so that generated keys are
// attested with the batch keys from the configured keybox. A factory batch keybox
// carries both an RSA and an EC key and each attested key is signed with the matching
// algorithm; an RKP-extracted keybox carries only an EC P-256 key, so every leaf
// (RSA keys included) is signed with the EC key, exactly as a real RKP device does.
// At least one key must be present, but neither is individually required.

use base64::{engine::general_purpose, Engine as _};
use kmr_common::{
    crypto::ec, crypto::rsa, crypto::CurveType, crypto::KeyMaterial, Error,
};
use kmr_ta::device::{RetrieveCertSigningInfo, SigningAlgorithm, SigningKeyType};
use kmr_wire::keymint::{self, EcCurve};
use roxmltree::Document;
use x509_cert::der::Decode;
use x509_cert::Certificate as X509Certificate;

/// Per-algorithm signing key material plus its certificate chain.
#[derive(Clone)]
struct AlgoInfo {
    key: KeyMaterial,
    chain: Vec<keymint::Certificate>,
}

/// Signing information for the asymmetric key types we attest with. Each algorithm is optional; a
/// keybox must carry at least one, but an RKP-extracted keybox legitimately has only the EC key.
#[derive(Clone)]
pub struct CertSignInfo {
    rsa: Option<AlgoInfo>,
    ec: Option<AlgoInfo>,
}

impl CertSignInfo {
    /// Choose the batch key for an attested key, preferring the matching algorithm (`prefer_ec`) and
    /// falling back to the other key when the keybox lacks the preferred one. Returns the key info
    /// plus whether the chosen key is EC, so callers stamp the signature fields for the key that
    /// actually signs rather than the key being attested. `new` guarantees at least one key exists,
    /// so the fallback is always present.
    fn pick(&self, prefer_ec: bool) -> (&AlgoInfo, bool) {
        let (primary, other) = if prefer_ec { (&self.ec, &self.rsa) } else { (&self.rsa, &self.ec) };
        match primary {
            Some(a) => (a, prefer_ec),
            None => (
                other.as_ref().expect("keybox has at least one signing key"),
                !prefer_ec,
            ),
        }
    }

    /// The batch signing key, its keybox certificate chain, and whether that key is EC. `prefer_ec`
    /// requests the algorithm matching the key being attested; when absent, the other key is used
    /// (an EC-only RKP keybox signs every leaf with its EC key). Patch mode re-signs a real
    /// attestation leaf with this key and appends this chain.
    pub fn batch(&self, prefer_ec: bool) -> (KeyMaterial, &[keymint::Certificate], bool) {
        let (a, is_ec) = self.pick(prefer_ec);
        (a.key.clone(), &a.chain, is_ec)
    }
}

impl CertSignInfo {
    /// Parse a keybox.xml string and extract whichever of the RSA and EC signing keys/chains it
    /// carries. Requires at least one; a factory keybox has both, an RKP-extracted keybox only EC.
    pub fn new(keybox_xml: &str) -> Result<Self, String> {
        let doc = Document::parse(keybox_xml).map_err(|e| format!("keybox parse: {e:?}"))?;

        let node = |algo: &str| {
            doc.descendants()
                .find(|n| n.has_tag_name("Key") && n.attribute("algorithm") == Some(algo))
        };

        // Load each algorithm independently. A key that is absent, malformed, or carries a chain
        // that is not valid DER is dropped rather than sinking the whole keybox: as long as one
        // usable key remains, leaves that would be signed with the dropped key fall back to it
        // (an EC-only RKP keybox already relies on that fallback for every RSA leaf).
        let rsa = load_algo(node("rsa"), SigningAlgorithm::Rsa);
        let ec = load_algo(node("ecdsa"), SigningAlgorithm::Ec);

        if rsa.is_none() && ec.is_none() {
            return Err(
                "keybox: no usable signing key (need a valid <Key algorithm=\"rsa\"> or \
                 <Key algorithm=\"ecdsa\">)"
                    .to_string(),
            );
        }

        let info = CertSignInfo { rsa, ec };
        log::info!(
            "teesim_km: keybox parsed (rsa={}, ec={})",
            info.rsa.is_some(),
            info.ec.is_some()
        );
        if let Some(a) = &info.rsa {
            crate::resign::log_chain("teesim_km: keybox RSA chain", &a.chain);
        }
        if let Some(a) = &info.ec {
            crate::resign::log_chain("teesim_km: keybox EC chain", &a.chain);
        }
        Ok(info)
    }
}

fn parse_algo(node: roxmltree::Node, algo: SigningAlgorithm) -> Result<AlgoInfo, String> {
    let name = algo_name(&algo);

    let priv_pem = node
        .children()
        .find(|n| n.has_tag_name("PrivateKey"))
        .ok_or_else(|| format!("{name}: missing PrivateKey"))?
        .text()
        .ok_or_else(|| format!("{name}: empty PrivateKey"))?;
    let key_der = decode_pem(priv_pem)?;

    let mut chain = Vec::new();
    for cert in node.descendants().filter(|n| n.has_tag_name("Certificate")) {
        let pem = cert.text().ok_or_else(|| format!("{name}: empty Certificate"))?;
        // A single <Certificate> element may concatenate several PEM blocks; decode each into its
        // own DER. Folding them into one base64 run would splice an inner block's `=` padding into
        // the middle of the stream and fail as `base64: InvalidByte(_, 61)`.
        for der in decode_pem_blocks(pem)? {
            chain.push(keymint::Certificate { encoded_certificate: der });
        }
    }
    if chain.len() < 2 {
        return Err(format!("{name}: expected at least 2 certificates, found {}", chain.len()));
    }

    let key = match algo {
        SigningAlgorithm::Rsa => KeyMaterial::Rsa(rsa::Key(key_der).into()),
        // Keyboxes in the field use NIST P-256 for the EC batch key.
        SigningAlgorithm::Ec => {
            KeyMaterial::Ec(EcCurve::P256, CurveType::Nist, ec::Key::P256(ec::NistKey(key_der)).into())
        }
    };
    Ok(AlgoInfo { key, chain })
}

/// The human-readable name of a signing algorithm, used in log lines.
fn algo_name(algo: &SigningAlgorithm) -> &'static str {
    match algo {
        SigningAlgorithm::Rsa => "RSA",
        SigningAlgorithm::Ec => "EC",
    }
}

/// Parse and validate one algorithm's key from its `<Key>` node, or return `None` when it is absent
/// or unusable. A present-but-broken key (bad base64, too few certs, or a chain whose leaf is not a
/// DER certificate) is dropped with a warning rather than failing the keybox, so the other key can
/// carry every leaf.
fn load_algo(node: Option<roxmltree::Node>, algo: SigningAlgorithm) -> Option<AlgoInfo> {
    let node = node?;
    let name = algo_name(&algo);
    let info = match parse_algo(node, algo) {
        Ok(info) => info,
        Err(e) => {
            log::warn!(
                "teesim_km: keybox {name} key is unusable ({e}); ignoring the {name} key — leaves \
                 that would be signed with it fall back to the keybox's other key"
            );
            return None;
        }
    };
    for (i, cert) in info.chain.iter().enumerate() {
        let der = &cert.encoded_certificate;
        if let Err(err) = X509Certificate::from_der(der).map(|_| ()) {
            log::warn!(
                "teesim_km: keybox {name} chain[{i}] is not a DER certificate ({}): {} byte(s) \
                 starting {}; ignoring the {name} key — leaves that would be signed with it fall \
                 back to the keybox's other key",
                err.kind(),
                der.len(),
                hex_preview(der)
            );
            return None;
        }
    }
    Some(info)
}

/// Format the first few bytes of `der` as space-separated hex, with a trailing ellipsis when more
/// bytes follow, e.g. `40 69 6e 74 65 67 72 69 …`.
fn hex_preview(der: &[u8]) -> String {
    const N: usize = 8;
    let mut s = der.iter().take(N).map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");
    if der.len() > N {
        s.push_str(" …");
    }
    s
}

/// Strip PEM armor and all whitespace, then base64-decode a single body. Used for key material,
/// which is one PEM block; the first block wins if several are present.
fn decode_pem(pem: &str) -> Result<Vec<u8>, String> {
    decode_pem_blocks(pem)?
        .into_iter()
        .next()
        .ok_or_else(|| "base64: empty PEM body".to_string())
}

/// Decode every PEM block in `pem` into its own DER blob. A body with no `-----BEGIN/END-----`
/// armor is decoded as a single blob. Each block's base64 is decoded separately so that an inner
/// block's `=` padding never lands in the middle of a concatenated stream.
fn decode_pem_blocks(pem: &str) -> Result<Vec<Vec<u8>>, String> {
    let mut blocks = Vec::new();
    let mut body = String::new();
    let mut in_block = false;
    let mut saw_armor = false;

    let flush = |body: &mut String, blocks: &mut Vec<Vec<u8>>| -> Result<(), String> {
        if body.is_empty() {
            return Ok(());
        }
        let der =
            general_purpose::STANDARD.decode(body.as_str()).map_err(|e| format!("base64: {e:?}"))?;
        body.clear();
        if !der.is_empty() {
            blocks.push(der);
        }
        Ok(())
    };

    for line in pem.lines() {
        let line = line.trim();
        if line.starts_with("-----BEGIN") {
            saw_armor = true;
            in_block = true;
            body.clear();
            continue;
        }
        if line.starts_with("-----END") {
            saw_armor = true;
            in_block = false;
            flush(&mut body, &mut blocks)?;
            continue;
        }
        if line.is_empty() {
            continue;
        }
        // Accumulate base64 while inside a block, or when the body carries no armor at all.
        if in_block || !saw_armor {
            body.extend(line.chars().filter(|c| !c.is_whitespace()));
        }
    }
    // A trailing unarmored body (no BEGIN/END lines) is one block.
    if !saw_armor {
        flush(&mut body, &mut blocks)?;
    }
    Ok(blocks)
}

impl RetrieveCertSigningInfo for CertSignInfo {
    fn signing_key(&self, key_type: SigningKeyType) -> Result<KeyMaterial, Error> {
        // kmr-ta derives the leaf's signature algorithm from the returned key material, so the EC
        // fallback for an RSA request on an EC-only keybox yields a correctly EC-signed leaf.
        let prefer_ec = matches!(key_type.algo_hint, SigningAlgorithm::Ec);
        Ok(self.pick(prefer_ec).0.key.clone())
    }

    fn cert_chain(&self, key_type: SigningKeyType) -> Result<Vec<keymint::Certificate>, Error> {
        let prefer_ec = matches!(key_type.algo_hint, SigningAlgorithm::Ec);
        Ok(self.pick(prefer_ec).0.chain.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose;

    #[test]
    fn multiple_pem_blocks_in_one_node_decode_separately() {
        // Two DER blobs whose base64 carries `=` padding; concatenating the base64 into one run
        // (the old behavior) would splice the first block's padding mid-stream and fail as
        // `base64: InvalidByte(_, 61)`. Decoding per block keeps them independent.
        let a = general_purpose::STANDARD.encode([0x30u8, 0x03, 0x02, 0x01, 0x05]);
        let b = general_purpose::STANDARD.encode([0x30u8, 0x82, 0x01, 0x02]);
        assert!(a.contains('='), "test fixture should exercise `=` padding");
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{a}\n-----END CERTIFICATE-----\n\
             -----BEGIN CERTIFICATE-----\n{b}\n-----END CERTIFICATE-----\n"
        );
        let blocks = decode_pem_blocks(&pem).expect("both blocks decode");
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0], [0x30, 0x03, 0x02, 0x01, 0x05]);
        assert_eq!(blocks[1], [0x30, 0x82, 0x01, 0x02]);
    }

    #[test]
    fn raw_base64_without_armor_is_one_block() {
        let raw = general_purpose::STANDARD.encode([0x30u8, 0x01, 0x02]);
        let blocks = decode_pem_blocks(&raw).expect("raw body decodes");
        assert_eq!(blocks, vec![vec![0x30, 0x01, 0x02]]);
    }

    #[test]
    fn decode_pem_returns_first_block() {
        let one = general_purpose::STANDARD.encode([0x30u8, 0x01, 0x02]);
        let pem = format!("-----BEGIN PRIVATE KEY-----\n{one}\n-----END PRIVATE KEY-----\n");
        assert_eq!(decode_pem(&pem).unwrap(), vec![0x30, 0x01, 0x02]);
    }

    #[test]
    fn hex_preview_caps_at_eight_bytes_with_ellipsis() {
        assert_eq!(hex_preview(&[0x40, 0x69, 0x6e]), "40 69 6e");
        assert_eq!(
            hex_preview(&[0x40, 0x69, 0x6e, 0x74, 0x65, 0x67, 0x72, 0x69, 0x74, 0x79]),
            "40 69 6e 74 65 67 72 69 …"
        );
    }
}
