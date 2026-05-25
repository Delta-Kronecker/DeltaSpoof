//! Byte-exact Rust port of upstream's `ClientHelloMaker`.
//!
//! Produces a 517-byte TLS 1.3 ClientHello whose only meaningfully variable
//! fields are the random, session-id, SNI value, and key_share. A length-padding
//! extension keeps the total record size constant for any SNI ≤ 219 bytes.

const TLS_CH_TEMPLATE_HEX: &str = "1603010200010001fc030341d5b549d9cd1adfa7296c8418d157dc7b624c842824ff493b9375bb48d34f2b20bf018bcc90a7c89a230094815ad0c15b736e38c01209d72d282cb5e2105328150024130213031301c02cc030c02bc02fcca9cca8c024c028c023c027009f009e006b006700ff0100018f0000000b00090000066d63692e6972000b000403000102000a00160014001d0017001e0019001801000101010201030104002300000010000e000c02683208687474702f312e310016000000170000000d002a0028040305030603080708080809080a080b080408050806040105010601030303010302040205020602002b00050403040303002d00020101003300260024001d0020435bacc4d05f9d41fef44ab3ad55616c36e0613473e2338770efdaa98693d217001500d5000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

/// Length of the produced ClientHello record. The padding extension makes
/// this a constant regardless of `target_sni` length (for SNI ≤ 219 bytes).
pub const CLIENT_HELLO_LEN: usize = 517;

/// Maximum supported SNI length (constrained by the padding extension).
pub const MAX_SNI_LEN: usize = 219;

/// Length of the upstream template's hard-coded `mci.ir` SNI.
const TEMPLATE_SNI_LEN: usize = 6;

fn template_bytes() -> &'static [u8] {
    use std::sync::OnceLock;
    static TEMPLATE: OnceLock<Vec<u8>> = OnceLock::new();
    TEMPLATE.get_or_init(|| {
        let bytes = TLS_CH_TEMPLATE_HEX.as_bytes();
        let mut out = Vec::with_capacity(bytes.len() / 2);
        let mut i = 0;
        while i < bytes.len() {
            let hi = (bytes[i] as char).to_digit(16).expect("hex");
            let lo = (bytes[i + 1] as char).to_digit(16).expect("hex");
            out.push(((hi << 4) | lo) as u8);
            i += 2;
        }
        out
    })
}

/// Build a TLS 1.3 ClientHello with the given random, session id, SNI, and key_share.
///
/// `random`, `session_id`, and `key_share` must each be exactly 32 bytes.
/// `target_sni` must be at most [`MAX_SNI_LEN`] bytes.
pub fn build_client_hello(
    random: &[u8],
    session_id: &[u8],
    target_sni: &[u8],
    key_share: &[u8],
) -> Vec<u8> {
    assert_eq!(random.len(), 32, "random must be 32 bytes");
    assert_eq!(session_id.len(), 32, "session_id must be 32 bytes");
    assert_eq!(key_share.len(), 32, "key_share must be 32 bytes");
    assert!(target_sni.len() <= MAX_SNI_LEN, "SNI too long");

    let template = template_bytes();
    // Mirror the slicing constants from upstream's Python implementation.
    let static1 = &template[..11];
    let static2: &[u8] = b"\x20";
    let static3 = &template[76..120];
    let static4 = &template[127 + TEMPLATE_SNI_LEN..262 + TEMPLATE_SNI_LEN];
    let static5: &[u8] = b"\x00\x15";

    let sni_len = target_sni.len();
    // server_name extension: outer (sni_len+5) | list_len (sni_len+3) | type=0 | name_len | name
    let mut server_name_ext = Vec::with_capacity(sni_len + 9);
    server_name_ext.extend_from_slice(&((sni_len + 5) as u16).to_be_bytes());
    server_name_ext.extend_from_slice(&((sni_len + 3) as u16).to_be_bytes());
    server_name_ext.push(0x00);
    server_name_ext.extend_from_slice(&(sni_len as u16).to_be_bytes());
    server_name_ext.extend_from_slice(target_sni);

    // padding extension: length=(219-sni_len) followed by zero bytes
    let pad_len = MAX_SNI_LEN - sni_len;
    let mut padding_ext = Vec::with_capacity(pad_len + 2);
    padding_ext.extend_from_slice(&(pad_len as u16).to_be_bytes());
    padding_ext.resize(2 + pad_len, 0);

    let mut out = Vec::with_capacity(CLIENT_HELLO_LEN);
    out.extend_from_slice(static1);
    out.extend_from_slice(random);
    out.extend_from_slice(static2);
    out.extend_from_slice(session_id);
    out.extend_from_slice(static3);
    out.extend_from_slice(&server_name_ext);
    out.extend_from_slice(static4);
    out.extend_from_slice(key_share);
    out.extend_from_slice(static5);
    out.extend_from_slice(&padding_ext);
    debug_assert_eq!(out.len(), CLIENT_HELLO_LEN);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_is_517_bytes_for_various_sni_lengths() {
        for sni in [
            "a".as_bytes().to_vec(),
            b"auth.vercel.com".to_vec(),
            b"mci.ir".to_vec(),
            "x".repeat(MAX_SNI_LEN).into_bytes(),
        ] {
            let out = build_client_hello(&[1u8; 32], &[2u8; 32], &sni, &[3u8; 32]);
            assert_eq!(out.len(), CLIENT_HELLO_LEN, "len for sni={}", sni.len());
        }
    }

    #[test]
    fn embeds_sni_at_expected_offset() {
        let sni = b"auth.vercel.com";
        let out = build_client_hello(&[0u8; 32], &[0u8; 32], sni, &[0u8; 32]);
        // Per upstream comment: SNI bytes start at offset 127.
        assert_eq!(&out[127..127 + sni.len()], sni);
        // random at 11..43, session id at 44..76
        assert_eq!(&out[11..43], &[0u8; 32]);
        assert_eq!(&out[44..76], &[0u8; 32]);
        // key_share at 262 + len(sni) .. +32
        let ks_off = 262 + sni.len();
        assert_eq!(&out[ks_off..ks_off + 32], &[0u8; 32]);
    }

    /// Golden vector: parse the upstream template back from itself.
    /// Reconstructing with the template's own SNI ("mci.ir") and the template's
    /// random/session_id/key_share must reproduce the template byte-for-byte.
    #[test]
    fn round_trips_upstream_template() {
        let template = template_bytes();
        assert_eq!(template.len(), CLIENT_HELLO_LEN);
        let random = &template[11..43];
        let session_id = &template[44..76];
        let sni = b"mci.ir";
        let ks_off = 262 + sni.len();
        let key_share = &template[ks_off..ks_off + 32];
        let rebuilt = build_client_hello(random, session_id, sni, key_share);
        assert_eq!(rebuilt, template);
    }
}
