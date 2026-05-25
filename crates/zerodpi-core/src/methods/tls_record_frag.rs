//! `tls_record_frag` bypass: splits the real TLS ClientHello into multiple
//! small TLS record-layer fragments before forwarding to the upstream server.
//!
//! ## How it works
//!
//! Many DPI/firewall middleboxes inspect TLS traffic by parsing TLS records
//! and extracting the SNI from the first `ClientHello` (record type `0x16`,
//! handshake type `0x01`).  If the ClientHello is spread across several TLS
//! records, engines that only reassemble up to a fixed depth (or none at all)
//! will not see the SNI in any single record and will classify the flow as
//! non-TLS or pass it through.
//!
//! This method intercepts the first outbound *data* packet (the real
//! ClientHello), splits its payload into chunks of at most
//! `TLS_RECORD_FRAG_SIZE` bytes, wraps each chunk in a new TLS record header,
//! and stages the concatenated result as the replacement payload.  The
//! upstream server receives all fragments in order and reassembles them
//! identically to an unfragmented ClientHello.
//!
//! Because no fake packet is injected, the bypass is signalled complete
//! immediately after the fragmented packet is emitted — no inbound ACK
//! confirmation is needed.
//!
//! ## Configuration
//!
//! | Key | Type | Default | Description |
//! |-----|------|---------|-------------|
//! | `TLS_RECORD_FRAG_SIZE` | `usize` | `1` | Max payload bytes per TLS record. |
//! | `TLS_RECORD_FRAG_SET_PSH` | `bool` | `true` | Set PSH on the modified packet. |
//! | `TLS_RECORD_FRAG_BUMP_IP_IDENT` | `bool` | `true` | Increment IPv4 ID. |

use tracing::trace;

use super::{BypassMethod, MethodAction};
use crate::config::Config;
use crate::flow::FlowState;
use crate::interceptor::PacketView;

pub struct TlsRecordFrag {
    /// Maximum bytes of payload placed in each TLS record fragment.
    frag_size: usize,
    /// Whether to set the TCP PSH flag on the modified packet.
    set_psh: bool,
    /// Whether to increment the IPv4 Identification field on the modified packet.
    bump_ip_ident: bool,
}

impl TlsRecordFrag {
    pub fn new(cfg: &Config) -> Self {
        Self {
            frag_size: cfg.TLS_RECORD_FRAG_SIZE,
            set_psh: cfg.TLS_RECORD_FRAG_SET_PSH,
            bump_ip_ident: cfg.TLS_RECORD_FRAG_BUMP_IP_IDENT,
        }
    }
}

impl BypassMethod for TlsRecordFrag {
    fn name(&self) -> &'static str {
        "tls_record_frag"
    }

    /// Returns `PassThrough` — this method operates on the first data packet,
    /// not the handshake-complete ACK.  The handler will set `waiting_for_data`
    /// on the flow and call [`on_first_data_packet`] instead.
    ///
    /// [`on_first_data_packet`]: TlsRecordFrag::on_first_data_packet
    fn on_handshake_complete_ack(
        &self,
        _flow: &FlowState,
        _pkt: &mut PacketView<'_>,
    ) -> MethodAction {
        MethodAction::PassThrough
    }

    /// Fragments the packet payload into multiple TLS records and stages the
    /// result, then returns `EmitFakeAndAccept` to signal bypass completion.
    fn on_first_data_packet(&self, _flow: &FlowState, pkt: &mut PacketView<'_>) -> MethodAction {
        let fragmented = fragment_payload(pkt.payload, self.frag_size);

        let mut flags = pkt.flags;
        flags.psh = self.set_psh;

        pkt.new_flags = Some(flags);
        pkt.new_payload = Some(fragmented);
        pkt.bump_ipv4_ident = self.bump_ip_ident;

        trace!(
            target = "zerodpi::tls_record_frag",
            frag_size = self.frag_size,
            orig_len = pkt.payload_len,
            set_psh = self.set_psh,
            bump_ip_ident = self.bump_ip_ident,
            "staged fragmented ClientHello"
        );

        MethodAction::emit_and_complete()
    }
}

/// Split `data` into TLS records of at most `frag_size` payload bytes each.
///
/// Each fragment is wrapped with a 5-byte TLS record header:
/// `[content_type][0x03][0x01][len_hi][len_lo]`
///
/// The `content_type` byte is taken from `data[0]` (preserving whatever
/// record type the caller sent: `0x16` for Handshake, `0x17` for
/// ApplicationData, etc.).  If `data` is empty, an empty `Vec` is returned.
///
/// # Panics
/// Panics if `frag_size == 0`.
pub fn fragment_payload(data: &[u8], frag_size: usize) -> Vec<u8> {
    assert!(frag_size > 0, "frag_size must be >= 1");
    if data.is_empty() {
        return Vec::new();
    }

    // Content-type byte from the first byte of the original data.
    let content_type = data[0];

    let num_frags = data.len().div_ceil(frag_size);
    // 5 header bytes per fragment + original data length.
    let capacity = 5 * num_frags + data.len();
    let mut out = Vec::with_capacity(capacity);

    for chunk in data.chunks(frag_size) {
        let len = chunk.len() as u16;
        out.push(content_type);
        out.push(0x03); // TLS major version
        out.push(0x01); // TLS minor version (TLS 1.0 record layer)
        out.push((len >> 8) as u8);
        out.push(len as u8);
        out.extend_from_slice(chunk);
    }
    out
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::flow::FlowState;
    use crate::interceptor::{Direction, PacketView, TcpFlags};

    fn default_cfg() -> Config {
        toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444"#,
        )
        .unwrap()
    }

    fn data_pkt(payload: &[u8]) -> PacketView<'_> {
        let payload_len = payload.len();
        PacketView {
            direction: Direction::Outbound,
            src_ip: Ipv4Addr::new(10, 0, 0, 1),
            dst_ip: Ipv4Addr::new(1, 2, 3, 4),
            src_port: 12345,
            dst_port: 443,
            seq: 1001,
            ack: 5001,
            flags: TcpFlags {
                ack: true,
                psh: true,
                ..Default::default()
            },
            payload_len,
            payload,
            new_seq: None,
            new_flags: None,
            new_payload: None,
            bump_ipv4_ident: false,
            corrupt_tcp_checksum_delta: None,
        }
    }

    // -----------------------------------------------------------------------
    // fragment_payload unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn empty_data_returns_empty() {
        assert!(fragment_payload(&[], 1).is_empty());
    }

    #[test]
    fn single_byte_frag_size_produces_one_record_per_byte() {
        // 3 bytes of payload → 3 records, each with a 5-byte header.
        let data = vec![0x16u8, 0xAA, 0xBB];
        let out = fragment_payload(&data, 1);
        assert_eq!(out.len(), 3 * 6); // 5-byte header + 1-byte chunk × 3
                                      // First record
        assert_eq!(out[0], 0x16); // content_type preserved
        assert_eq!(out[1], 0x03);
        assert_eq!(out[2], 0x01);
        assert_eq!(&out[3..5], &[0x00, 0x01]); // length = 1
        assert_eq!(out[5], 0x16); // payload byte
                                  // Second record
        assert_eq!(out[6], 0x16);
        assert_eq!(&out[9..11], &[0x00, 0x01]);
        assert_eq!(out[11], 0xAA);
    }

    #[test]
    fn frag_size_larger_than_data_produces_one_record() {
        let data = vec![0x16u8; 10];
        let out = fragment_payload(&data, 100);
        // 1 record: 5-byte header + 10 payload bytes
        assert_eq!(out.len(), 15);
        assert_eq!(out[0], 0x16);
        assert_eq!(&out[3..5], &[0x00, 0x0A]); // length = 10
    }

    #[test]
    fn frag_size_exactly_divides_data() {
        // 6 bytes, frag_size=2 → 3 records of 2 bytes each.
        let data = vec![0x17u8, 1, 2, 3, 4, 5];
        let out = fragment_payload(&data, 2);
        assert_eq!(out.len(), 3 * 7); // 5 header + 2 payload × 3
        for i in 0..3 {
            let off = i * 7;
            assert_eq!(out[off], 0x17);
            assert_eq!(&out[off + 3..off + 5], &[0x00, 0x02]);
        }
    }

    #[test]
    fn frag_size_does_not_divide_evenly() {
        // 7 bytes, frag_size=3 → 2 records of 3 + 1 record of 1.
        let data = vec![0x16u8; 7];
        let out = fragment_payload(&data, 3);
        // (5+3) + (5+3) + (5+1) = 22
        assert_eq!(out.len(), 22);
        // Last record starts at byte 16: 2 × (5-hdr + 3-payload) = 16.
        // Its length field is at offset 16+3 = 19.
        let last_hdr_off = (5 + 3) * 2; // = 16
        assert_eq!(&out[last_hdr_off + 3..last_hdr_off + 5], &[0x00, 0x01]);
    }

    #[test]
    fn content_type_is_preserved_from_first_byte() {
        let mut data = vec![0x17u8]; // ApplicationData type
        data.extend_from_slice(&[0u8; 10]);
        let out = fragment_payload(&data, 4);
        for chunk_idx in 0..out.len() / 9 {
            assert_eq!(
                out[chunk_idx * 9],
                0x17,
                "content_type mismatch in fragment {chunk_idx}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // BypassMethod integration tests
    // -----------------------------------------------------------------------

    #[test]
    fn on_handshake_complete_ack_is_passthrough() {
        let cfg = default_cfg();
        let method = TlsRecordFrag::new(&cfg);
        let state = FlowState::new(vec![]);
        let mut pkt = data_pkt(&[]);
        let action = method.on_handshake_complete_ack(&state, &mut pkt);
        assert_eq!(action, MethodAction::PassThrough);
    }

    #[test]
    fn on_first_data_packet_fragments_and_emits() {
        let cfg = default_cfg(); // TLS_RECORD_FRAG_SIZE = 1 by default
        let method = TlsRecordFrag::new(&cfg);
        let state = FlowState::new(vec![]);

        let payload = vec![0x16u8; 12]; // 12 bytes of fake ClientHello
        let mut pkt = data_pkt(&payload);
        let action = method.on_first_data_packet(&state, &mut pkt);

        assert_eq!(action, MethodAction::emit_and_complete());
        let new_payload = pkt.new_payload.as_ref().unwrap();
        // 12 bytes → 12 records of 1 byte each, each with 5-byte header → 72 bytes
        assert_eq!(new_payload.len(), 12 * 6);
        // Verify each record header
        for i in 0..12 {
            let off = i * 6;
            assert_eq!(new_payload[off], 0x16);
            assert_eq!(new_payload[off + 1], 0x03);
            assert_eq!(new_payload[off + 2], 0x01);
            assert_eq!(&new_payload[off + 3..off + 5], &[0x00, 0x01]);
            assert_eq!(new_payload[off + 5], 0x16);
        }
        assert!(pkt.new_flags.unwrap().psh); // default SET_PSH = true
        assert!(pkt.bump_ipv4_ident); // default BUMP_IP_IDENT = true
    }

    #[test]
    fn configurable_frag_size() {
        let mut cfg = default_cfg();
        cfg.TLS_RECORD_FRAG_SIZE = 5;
        let method = TlsRecordFrag::new(&cfg);
        let state = FlowState::new(vec![]);

        // 10-byte payload → 2 records of 5 bytes each
        let payload = vec![0x16u8; 10];
        let mut pkt = data_pkt(&payload);
        method.on_first_data_packet(&state, &mut pkt);
        let new_payload = pkt.new_payload.unwrap();
        assert_eq!(new_payload.len(), 2 * (5 + 5)); // 2 × (5-hdr + 5-payload)
    }

    #[test]
    fn set_psh_false() {
        let mut cfg = default_cfg();
        cfg.TLS_RECORD_FRAG_SET_PSH = false;
        let method = TlsRecordFrag::new(&cfg);
        let state = FlowState::new(vec![]);
        let payload = vec![0x16u8; 4];
        let mut pkt = data_pkt(&payload);
        method.on_first_data_packet(&state, &mut pkt);
        assert!(!pkt.new_flags.unwrap().psh);
    }

    #[test]
    fn bump_ip_ident_false() {
        let mut cfg = default_cfg();
        cfg.TLS_RECORD_FRAG_BUMP_IP_IDENT = false;
        let method = TlsRecordFrag::new(&cfg);
        let state = FlowState::new(vec![]);
        let payload = vec![0x16u8; 4];
        let mut pkt = data_pkt(&payload);
        method.on_first_data_packet(&state, &mut pkt);
        assert!(!pkt.bump_ipv4_ident);
    }
}
