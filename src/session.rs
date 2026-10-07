//! TPAP session layer: key schedule and AES-128-CCM request/response framing.
//!
//! Wire format of an encrypted request body: `BE32(seq) || ciphertext || tag`
//! (16-byte tag, no AAD), with nonce `base_nonce[..8] || BE32(seq)`.

use aes::Aes128;
use ccm::{
    Ccm,
    aead::{Aead, KeyInit, Payload},
    consts::{U12, U16},
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

type Aes128Ccm = Ccm<Aes128, U16, U12>;

const KEY_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("response payload too short")]
    TooShort,
    #[error("decryption failed (bad key, nonce or tag)")]
    Decrypt,
    #[error("encryption failed")]
    Encrypt,
    #[error("request sequence number exhausted")]
    SequenceExhausted,
}

/// A decoded device reply.
#[derive(Debug, PartialEq, Eq)]
pub enum Reply {
    /// Body began with `{` or `[`: an unencrypted JSON (error) envelope.
    Plain(Vec<u8>),
    /// Successfully decrypted JSON payload.
    Decrypted(Vec<u8>),
}

pub struct Session {
    key: Zeroizing<[u8; KEY_LEN]>,
    base_nonce: [u8; NONCE_LEN],
    next_seq: u32,
}

fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) {
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, out)
        .expect("output length within HKDF limit");
}

/// `base_nonce[..8] || BE32(seq)`.
fn nonce_for(base: &[u8; NONCE_LEN], seq: u32) -> [u8; NONCE_LEN] {
    let mut nonce = *base;
    nonce[NONCE_LEN - 4..].copy_from_slice(&seq.to_be_bytes());
    nonce
}

impl Session {
    /// Derive session keys from the SPAKE2+ shared key. `start_seq` is the
    /// device's `start_seq` from `pake_share`.
    pub fn new(shared_key: &[u8], start_seq: u32) -> Self {
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        let mut base_nonce = [0u8; NONCE_LEN];
        hkdf_sha256(
            shared_key,
            b"tp-kdf-salt-aes128-key",
            b"tp-kdf-info-aes128-key",
            key.as_mut_slice(),
        );
        hkdf_sha256(
            shared_key,
            b"tp-kdf-salt-aes128-iv",
            b"tp-kdf-info-aes128-iv",
            &mut base_nonce,
        );
        Self {
            key,
            base_nonce,
            next_seq: start_seq,
        }
    }

    /// Sequence number the next request will use.
    pub fn next_seq(&self) -> u32 {
        self.next_seq
    }

    /// Encrypt a request; returns `(sequence_used, body)`. The sequence
    /// counter advances for every request, including keep-alives.
    pub fn encrypt_request(&mut self, plaintext: &[u8]) -> Result<(u32, Vec<u8>), SessionError> {
        let seq = self.next_seq;
        let next = seq.checked_add(1).ok_or(SessionError::SequenceExhausted)?;
        let nonce = nonce_for(&self.base_nonce, seq);
        let cipher = Aes128Ccm::new_from_slice(self.key.as_slice()).expect("16-byte key");
        let sealed = cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: plaintext,
                    aad: &[],
                },
            )
            .map_err(|_| SessionError::Encrypt)?;
        self.next_seq = next;
        let mut body = Vec::with_capacity(4 + sealed.len());
        body.extend_from_slice(&seq.to_be_bytes());
        body.extend_from_slice(&sealed);
        Ok((seq, body))
    }

    /// Decode a device reply to the request sent with `request_seq`.
    pub fn decrypt_response(&self, body: &[u8], request_seq: u32) -> Result<Reply, SessionError> {
        // The first byte of an encrypted reply is the top byte of its sequence
        // number, which may itself be `{` or `[`; only a body that parses as
        // complete JSON is a plaintext envelope.
        if matches!(body.first(), Some(b'{') | Some(b'['))
            && serde_json::from_slice::<serde_json::Value>(body).is_ok()
        {
            return Ok(Reply::Plain(body.to_vec()));
        }
        if body.len() < 4 + TAG_LEN {
            return Err(SessionError::TooShort);
        }
        let response_seq = u32::from_be_bytes(body[..4].try_into().expect("4 bytes"));
        // A zero response sequence means "same as the request".
        let seq = if response_seq == 0 {
            request_seq
        } else {
            response_seq
        };
        let nonce = nonce_for(&self.base_nonce, seq);
        let cipher = Aes128Ccm::new_from_slice(self.key.as_slice()).expect("16-byte key");
        let plain = cipher
            .decrypt(
                (&nonce).into(),
                Payload {
                    msg: &body[4..],
                    aad: &[],
                },
            )
            .map_err(|_| SessionError::Decrypt)?;
        Ok(Reply::Decrypted(plain))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Vectors below were generated independently with Python `cryptography`
    // (HKDF-SHA256 and AESCCM) from shared_key = 00 01 .. 1f.
    fn shared_key() -> Vec<u8> {
        (0u8..32).collect()
    }

    #[test]
    fn key_schedule_known_answer() {
        let s = Session::new(&shared_key(), 0);
        assert_eq!(hex::encode(*s.key), KEY_HEX);
        assert_eq!(hex::encode(s.base_nonce), NONCE_HEX);
    }

    #[test]
    fn nonce_layout_known_answer() {
        let s = Session::new(&shared_key(), 0);
        let nonce = nonce_for(&s.base_nonce, 0x0102_0304);
        assert_eq!(&nonce[..8], &s.base_nonce[..8]);
        assert_eq!(&nonce[8..], &[1, 2, 3, 4]);
    }

    #[test]
    fn request_known_answer() {
        let mut s = Session::new(&shared_key(), 0x0000_0102);
        let (seq, body) = s
            .encrypt_request(br#"{"method":"get_device_info"}"#)
            .unwrap();
        assert_eq!(seq, 0x102);
        assert_eq!(hex::encode(&body), REQUEST_HEX);
    }

    #[test]
    fn sequence_increments_per_request() {
        let mut s = Session::new(&shared_key(), 10);
        let (a, _) = s.encrypt_request(b"{}").unwrap();
        let (b, _) = s.encrypt_request(b"{}").unwrap();
        let (c, _) = s.encrypt_request(b"{}").unwrap();
        assert_eq!((a, b, c), (10, 11, 12));
        assert_eq!(s.next_seq(), 13);
    }

    #[test]
    fn same_plaintext_different_seq_gives_different_ciphertext() {
        let mut s = Session::new(&shared_key(), 1);
        let (_, a) = s.encrypt_request(b"{}").unwrap();
        let (_, b) = s.encrypt_request(b"{}").unwrap();
        assert_ne!(a[4..], b[4..]);
    }

    #[test]
    fn sequence_exhaustion_is_an_error_and_does_not_advance() {
        let mut s = Session::new(&shared_key(), u32::MAX);
        assert!(matches!(
            s.encrypt_request(b"{}"),
            Err(SessionError::SequenceExhausted)
        ));
        assert_eq!(s.next_seq(), u32::MAX);
    }

    #[test]
    fn response_roundtrip_with_explicit_and_zero_sequence() {
        let mut dev = Session::new(&shared_key(), 5);
        let client = Session::new(&shared_key(), 5);
        // The device encrypts replies the same way; reuse encrypt_request.
        let (seq, body) = dev.encrypt_request(br#"{"error_code":0}"#).unwrap();
        assert_eq!(
            client.decrypt_response(&body, 999).unwrap(),
            Reply::Decrypted(br#"{"error_code":0}"#.to_vec())
        );
        // A zero response sequence falls back to the request sequence: the
        // body was sealed under seq 5, so request_seq 5 decrypts it...
        let mut zero = body.clone();
        zero[..4].copy_from_slice(&0u32.to_be_bytes());
        assert_eq!(
            client.decrypt_response(&zero, seq).unwrap(),
            Reply::Decrypted(br#"{"error_code":0}"#.to_vec())
        );
        // ...and any other request sequence does not.
        assert!(client.decrypt_response(&zero, seq + 1).is_err());
    }

    #[test]
    fn plaintext_error_envelope_is_passed_through() {
        let s = Session::new(&shared_key(), 0);
        assert_eq!(
            s.decrypt_response(br#"{"error_code":-40401}"#, 1).unwrap(),
            Reply::Plain(br#"{"error_code":-40401}"#.to_vec())
        );
    }

    #[test]
    fn encrypted_replies_whose_sequence_starts_with_a_json_byte_still_decrypt() {
        for start in [0x7b00_0064u32, 0x5b00_0064, 0x7bff_ffff, 0x5b00_0000] {
            let mut dev = Session::new(&shared_key(), start);
            let client = Session::new(&shared_key(), start);
            let (seq, body) = dev.encrypt_request(br#"{"error_code":0}"#).unwrap();
            assert!(matches!(body[0], b'{' | b'['));
            assert_eq!(
                client.decrypt_response(&body, seq).unwrap(),
                Reply::Decrypted(br#"{"error_code":0}"#.to_vec()),
                "start {start:#x}"
            );
        }
    }

    #[test]
    fn truncated_json_looking_body_is_not_plaintext() {
        let s = Session::new(&shared_key(), 0);
        assert!(s.decrypt_response(br#"{"error_code":"#, 1).is_err());
    }

    #[test]
    fn tampering_and_truncation_are_rejected() {
        let mut dev = Session::new(&shared_key(), 3);
        let client = Session::new(&shared_key(), 3);
        let (seq, mut body) = dev.encrypt_request(b"{\"a\":1}").unwrap();
        assert!(matches!(
            client.decrypt_response(&body[..10], seq),
            Err(SessionError::TooShort)
        ));
        *body.last_mut().unwrap() ^= 1;
        assert!(matches!(
            client.decrypt_response(&body, seq),
            Err(SessionError::Decrypt)
        ));
    }

    #[test]
    fn wrong_key_is_rejected() {
        let mut dev = Session::new(&shared_key(), 3);
        let other = Session::new(&[0xAA; 32], 3);
        let (seq, body) = dev.encrypt_request(b"{\"a\":1}").unwrap();
        assert!(other.decrypt_response(&body, seq).is_err());
    }

    const KEY_HEX: &str = "1f477a8c3d031511dcfd57aa01895887";
    const NONCE_HEX: &str = "4240c38bb08a77faaae56105";
    const REQUEST_HEX: &str = "00000102745e7750d8d965cc0f0e784d4eac2955e8b7ee171d09e13065a245e01693ec9fdb4d3675729ff33d5d91b4fc";
}
