//! TPAP's SPAKE2+ variant over P-256 (client/prover side).
//!
//! This follows the observed wire behaviour of the TPAP handshake, which is
//! *not* plain RFC 9383: the PBKDF2 output is split 40/40 bytes, the context
//! string is `"PAKE V1" || user_random || dev_random`, and `w0` enters the
//! transcript in a variable-length encoding (see [`encode_w0`]).

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use p256::{
    AffinePoint, ProjectivePoint, Scalar,
    elliptic_curve::{
        Field,
        sec1::{FromSec1Point, ToSec1Point},
    },
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// RFC 9383 P-256 `M` point (compressed SEC1).
pub const M_COMPRESSED: [u8; 33] = [
    0x02, 0x88, 0x6e, 0x2f, 0x97, 0xac, 0xe4, 0x6e, 0x55, 0xba, 0x9d, 0xd7, 0x24, 0x25, 0x79, 0xf2,
    0x99, 0x3b, 0x64, 0xe1, 0x6e, 0xf3, 0xdc, 0xab, 0x95, 0xaf, 0xd4, 0x97, 0x33, 0x3d, 0x8f, 0xa1,
    0x2f,
];
/// RFC 9383 P-256 `N` point (compressed SEC1).
pub const N_COMPRESSED: [u8; 33] = [
    0x03, 0xd8, 0xbb, 0xd6, 0xc6, 0x39, 0xc6, 0x29, 0x37, 0xb0, 0x4d, 0x99, 0x7f, 0x38, 0xc3, 0x77,
    0x07, 0x19, 0xc6, 0x29, 0xd7, 0x01, 0x4d, 0x49, 0xa2, 0x4b, 0x4f, 0x98, 0xba, 0xa1, 0x29, 0x2b,
    0x49,
];

/// Length of one PBKDF2 slice (`hashLength + 8` for SHA-256).
const W_SLICE_LEN: usize = 40;
const CONTEXT_TAG: &[u8] = b"PAKE V1";

#[derive(Debug, thiserror::Error)]
pub enum SpakeError {
    #[error("invalid elliptic curve point")]
    InvalidPoint,
    #[error("PBKDF2 iteration count must be positive")]
    BadIterations,
    #[error("random number generation failed")]
    Rng,
}

/// Client secrets derived from the credential string.
pub struct WValues {
    pub w0: Scalar,
    pub w1: Scalar,
}

/// Everything the client needs after processing the device's share.
pub struct Handshake {
    /// Client share `L`, uncompressed SEC1 (65 bytes), sent as `user_share`.
    pub user_share: Vec<u8>,
    /// MAC sent as `user_confirm`.
    pub user_confirm: Vec<u8>,
    /// MAC the device must send back as `dev_confirm`.
    pub expected_dev_confirm: Vec<u8>,
    /// SPAKE2+ shared key; input to the session key schedule.
    pub shared_key: Zeroizing<Vec<u8>>,
}

impl Handshake {
    /// Constant-time check of the device's confirmation MAC.
    pub fn verify_dev_confirm(&self, dev_confirm: &[u8]) -> bool {
        self.expected_dev_confirm.ct_eq(dev_confirm).into()
    }
}

/// Reduce big-endian bytes modulo the P-256 group order.
fn scalar_from_be_wide(bytes: &[u8]) -> Scalar {
    let base = Scalar::from(256u64);
    bytes.iter().fold(Scalar::ZERO, |acc, b| {
        acc * base + Scalar::from(u64::from(*b))
    })
}

/// Derive `w0`/`w1` from the credential string, device salt and iteration count.
pub fn derive_w(credentials: &[u8], salt: &[u8], iterations: u32) -> Result<WValues, SpakeError> {
    if iterations == 0 {
        return Err(SpakeError::BadIterations);
    }
    let mut derived = Zeroizing::new([0u8; 2 * W_SLICE_LEN]);
    pbkdf2::pbkdf2_hmac::<Sha256>(credentials, salt, iterations, derived.as_mut_slice());
    Ok(WValues {
        w0: scalar_from_be_wide(&derived[..W_SLICE_LEN]),
        w1: scalar_from_be_wide(&derived[W_SLICE_LEN..]),
    })
}

/// Draw a uniformly random non-zero scalar from the OS RNG.
pub fn random_scalar() -> Result<Scalar, SpakeError> {
    loop {
        // 48 bytes of entropy reduced mod n: bias is negligible (< 2^-128).
        let mut buf = Zeroizing::new([0u8; 48]);
        getrandom::fill(buf.as_mut_slice()).map_err(|_| SpakeError::Rng)?;
        let s = scalar_from_be_wide(buf.as_slice());
        if !bool::from(s.is_zero()) {
            return Ok(s);
        }
    }
}

/// Decode a SEC1 point; the point at infinity is rejected, since no protocol
/// value (M, N, or a peer's share) may be the identity.
pub fn decode_point(bytes: &[u8]) -> Result<ProjectivePoint, SpakeError> {
    let point = AffinePoint::from_sec1_bytes(bytes)
        .map(ProjectivePoint::from)
        .map_err(|_| SpakeError::InvalidPoint)?;
    if point == ProjectivePoint::IDENTITY {
        return Err(SpakeError::InvalidPoint);
    }
    Ok(point)
}

pub fn encode_point(point: &ProjectivePoint) -> Vec<u8> {
    point.to_affine().to_sec1_point(false).as_bytes().to_vec()
}

/// TPAP's `w0` transcript encoding: minimal unsigned big-endian bytes, where
/// zero is `[0]`; an even length is used as-is; an odd length gets a leading
/// `0x00` only when the top bit is set. (Mirrors the reference client's
/// `EncodeW`; deliberately not RFC 9383's fixed-width encoding.)
pub fn encode_w0(w0: &Scalar) -> Vec<u8> {
    let bytes = w0.to_bytes();
    let first = bytes.iter().position(|b| *b != 0);
    let unsigned: Vec<u8> = match first {
        Some(i) => bytes[i..].to_vec(),
        None => vec![0],
    };
    if unsigned.len().is_multiple_of(2) {
        return unsigned;
    }
    if unsigned[0] & 0x80 != 0 {
        let mut out = Vec::with_capacity(unsigned.len() + 1);
        out.push(0);
        out.extend_from_slice(&unsigned);
        return out;
    }
    unsigned
}

fn len8_le(out: &mut Vec<u8>, item: &[u8]) {
    out.extend_from_slice(&(item.len() as u64).to_le_bytes());
    out.extend_from_slice(item);
}

pub(crate) fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// HKDF-SHA256 with a zero salt (the reference's `HkdfExpand`): extract then expand.
fn hkdf_zero_salt(ikm: &[u8], info: &[u8], len: usize) -> Zeroizing<Vec<u8>> {
    let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), ikm);
    let mut out = Zeroizing::new(vec![0u8; len]);
    hk.expand(info, out.as_mut_slice())
        .expect("output length within HKDF limit");
    out
}

/// SHA-256 over the TPAP SPAKE2+ transcript TT.
#[allow(clippy::too_many_arguments)]
pub(crate) fn transcript_hash(
    user_random: &[u8],
    dev_random: &[u8],
    m: &ProjectivePoint,
    n: &ProjectivePoint,
    l_enc: &[u8],
    r_enc: &[u8],
    z: &ProjectivePoint,
    v: &ProjectivePoint,
    w0: &Scalar,
) -> Vec<u8> {
    let mut context = Vec::with_capacity(CONTEXT_TAG.len() + user_random.len() + dev_random.len());
    context.extend_from_slice(CONTEXT_TAG);
    context.extend_from_slice(user_random);
    context.extend_from_slice(dev_random);
    let context_hash = Sha256::digest(&context);

    let mut tt = Vec::new();
    len8_le(&mut tt, &context_hash);
    len8_le(&mut tt, &[]);
    len8_le(&mut tt, &[]);
    len8_le(&mut tt, &encode_point(m));
    len8_le(&mut tt, &encode_point(n));
    len8_le(&mut tt, l_enc);
    len8_le(&mut tt, r_enc);
    len8_le(&mut tt, &encode_point(z));
    len8_le(&mut tt, &encode_point(v));
    len8_le(&mut tt, &encode_w0(w0));
    Sha256::digest(&tt).to_vec()
}

/// `(KcA, KcB, SharedKey)` from the transcript hash.
pub(crate) fn confirmation_material(th: &[u8]) -> (Vec<u8>, Vec<u8>, Zeroizing<Vec<u8>>) {
    let keys = hkdf_zero_salt(th, b"ConfirmationKeys", 64);
    (
        keys[..32].to_vec(),
        keys[32..].to_vec(),
        hkdf_zero_salt(th, b"SharedKey", 32),
    )
}

/// Client share `L = x*G + w0*M`, uncompressed.
pub fn client_share(x: &Scalar, w0: &Scalar) -> Result<Vec<u8>, SpakeError> {
    let m = decode_point(&M_COMPRESSED)?;
    Ok(encode_point(&(ProjectivePoint::GENERATOR * x + m * w0)))
}

/// Finish the client side given the device's `dev_share`, `user_random`
/// and `dev_random`, using client scalar `x`.
pub fn finish(
    x: &Scalar,
    w: &WValues,
    user_random: &[u8],
    dev_random: &[u8],
    dev_share: &[u8],
) -> Result<Handshake, SpakeError> {
    let m = decode_point(&M_COMPRESSED)?;
    let n = decode_point(&N_COMPRESSED)?;
    let l = ProjectivePoint::GENERATOR * x + m * w.w0;
    let l_enc = encode_point(&l);

    let r = decode_point(dev_share)?;
    let r_enc = encode_point(&r);
    let r_prime = r - n * w.w0;
    let z = r_prime * x;
    let v = r_prime * w.w1;
    // RFC 9383: abort if the shared points are the identity. A share crafted as
    // w0*N makes R' the identity, so Z and V would no longer depend on any
    // secret of ours.
    let identity = ProjectivePoint::IDENTITY;
    if r_prime == identity || z == identity || v == identity {
        return Err(SpakeError::InvalidPoint);
    }

    let th = transcript_hash(
        user_random,
        dev_random,
        &m,
        &n,
        &l_enc,
        &r_enc,
        &z,
        &v,
        &w.w0,
    );
    let (kc_a, kc_b, shared_key) = confirmation_material(&th);

    Ok(Handshake {
        user_confirm: hmac_sha256(&kc_a, &r_enc),
        expected_dev_confirm: hmac_sha256(&kc_b, &l_enc),
        user_share: l_enc,
        shared_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar_from_u64(v: u64) -> Scalar {
        Scalar::from(v)
    }

    #[test]
    fn m_and_n_are_valid_points() {
        assert!(decode_point(&M_COMPRESSED).is_ok());
        assert!(decode_point(&N_COMPRESSED).is_ok());
    }

    #[test]
    fn rejects_garbage_point() {
        assert!(decode_point(&[0x04; 65]).is_err());
        assert!(decode_point(&[]).is_err());
    }

    #[test]
    fn w0_encoding_rules() {
        // zero -> [0]
        assert_eq!(encode_w0(&Scalar::ZERO), vec![0]);
        // 1 byte, top bit clear, odd length -> unchanged
        assert_eq!(encode_w0(&scalar_from_u64(0x7f)), vec![0x7f]);
        // 1 byte, top bit set, odd length -> leading zero
        assert_eq!(encode_w0(&scalar_from_u64(0x80)), vec![0x00, 0x80]);
        // 2 bytes, even -> unchanged even if top bit set
        assert_eq!(encode_w0(&scalar_from_u64(0xff01)), vec![0xff, 0x01]);
        // 3 bytes, top bit clear -> unchanged
        assert_eq!(
            encode_w0(&scalar_from_u64(0x010203)),
            vec![0x01, 0x02, 0x03]
        );
        // 3 bytes, top bit set -> leading zero
        assert_eq!(
            encode_w0(&scalar_from_u64(0x810203)),
            vec![0x00, 0x81, 0x02, 0x03]
        );
    }

    #[test]
    fn wide_reduction_matches_modulus() {
        // n itself reduces to zero; n + 5 reduces to 5.
        let n_hex = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
        let mut n = hex::decode(n_hex).unwrap();
        assert!(bool::from(scalar_from_be_wide(&n).is_zero()));
        *n.last_mut().unwrap() = n.last().unwrap().wrapping_add(5);
        assert_eq!(scalar_from_be_wide(&n), scalar_from_u64(5));
    }

    #[test]
    fn derive_w_rejects_zero_iterations() {
        assert!(matches!(
            derive_w(b"pw", b"salt", 0),
            Err(SpakeError::BadIterations)
        ));
    }

    /// Device (verifier) side, written independently of `finish`, to prove the
    /// two ends agree on confirmations and the shared key.
    #[test]
    fn client_and_device_agree() {
        let w = derive_w(b"user@example.com/hunter2", b"0123456789abcdef", 1000).unwrap();
        let x = random_scalar().unwrap();
        let y = random_scalar().unwrap();
        let user_random = [7u8; 32];
        let dev_random = [9u8; 32];

        let m = decode_point(&M_COMPRESSED).unwrap();
        let n = decode_point(&N_COMPRESSED).unwrap();
        let big_l_w1 = ProjectivePoint::GENERATOR * w.w1;
        // Device share R = y*G + w0*N.
        let r = ProjectivePoint::GENERATOR * y + n * w.w0;
        let dev_share = encode_point(&r);

        let hs = finish(&x, &w, &user_random, &dev_random, &dev_share).unwrap();

        // Device computes Z = y*(L - w0*M), V = y*(w1*G).
        let l = decode_point(&hs.user_share).unwrap();
        let z = (l - m * w.w0) * y;
        let v = big_l_w1 * y;

        let mut ctx = Vec::new();
        ctx.extend_from_slice(b"PAKE V1");
        ctx.extend_from_slice(&user_random);
        ctx.extend_from_slice(&dev_random);
        let mut tt = Vec::new();
        len8_le(&mut tt, &Sha256::digest(&ctx));
        len8_le(&mut tt, &[]);
        len8_le(&mut tt, &[]);
        len8_le(&mut tt, &encode_point(&m));
        len8_le(&mut tt, &encode_point(&n));
        len8_le(&mut tt, &hs.user_share);
        len8_le(&mut tt, &dev_share);
        len8_le(&mut tt, &encode_point(&z));
        len8_le(&mut tt, &encode_point(&v));
        len8_le(&mut tt, &encode_w0(&w.w0));
        let th = Sha256::digest(&tt);
        let ck = hkdf_zero_salt(&th, b"ConfirmationKeys", 64);
        let dev_confirm = hmac_sha256(&ck[32..], &hs.user_share);
        assert!(hs.verify_dev_confirm(&dev_confirm));
        assert_eq!(hmac_sha256(&ck[..32], &dev_share), hs.user_confirm);
        assert_eq!(*hkdf_zero_salt(&th, b"SharedKey", 32), *hs.shared_key);
    }

    /// Known-answer test: expected values come from the independent pure-Python
    /// model in `tools/gen_spake_vector.py` (fixed x and y, 1000 iterations).
    #[test]
    fn full_handshake_known_answer() {
        let w = derive_w(
            b"user@example.com/hunter2",
            &(0u8..16).collect::<Vec<_>>(),
            1000,
        )
        .unwrap();
        assert_eq!(
            hex::encode(w.w0.to_bytes()),
            "6b73d6e8daa1852a9523f409742e9d0954f84797e628e159109bb40c6b631b35"
        );
        assert_eq!(
            hex::encode(w.w1.to_bytes()),
            "994d0b1eb5265b6253e5c2e224d29daae5764130b746455f4a1d6a9dcad92f98"
        );
        let x = scalar_from_be_wide(&[0x11; 32]);
        let dev_share = hex::decode("04e8569d9f164ba7e5535ef1262e03f833c5cae9a3d860bba082e8bf305eef9d24355168bf8b4e4f5038d230aabb36be8b20f058494205ad2a25bc15eae03d46ed").unwrap();
        let hs = finish(&x, &w, &[7; 32], &[9; 32], &dev_share).unwrap();
        assert_eq!(
            hex::encode(&hs.user_share),
            "043136b0a65c4ccbe1d5ee4eccbc9ca726799a0446815936ad2d387b4c310924ad70b810630220729c407417d460b4d05ad0fc1038749595edc1e36f00e19c9245"
        );
        assert_eq!(
            hex::encode(&hs.user_confirm),
            "dbb2147d3090c65381b8187112c44b3f44848dcedd7bf5e3ee6bbe16f0105aeb"
        );
        assert_eq!(
            hex::encode(&hs.expected_dev_confirm),
            "fba3410894b2494069e071d3dcc2b681588ecbe9ff2c3ded51f7b33f4eb7fe28"
        );
        assert_eq!(
            hex::encode(&*hs.shared_key),
            "2a1c88dc9cde5b4952fd5f40cd4d24f597066878fc25cc1e04532a8581b8892b"
        );
    }

    #[test]
    fn identity_shared_points_are_rejected() {
        let w = derive_w(b"pw", b"salt-salt-salt", 10).unwrap();
        let x = random_scalar().unwrap();
        let n = decode_point(&N_COMPRESSED).unwrap();
        // R = w0*N, so R' = R - w0*N is the identity point.
        let crafted = encode_point(&(n * w.w0));
        assert!(matches!(
            finish(&x, &w, &[1; 32], &[2; 32], &crafted),
            Err(SpakeError::InvalidPoint)
        ));
        // The point at infinity itself is not an acceptable share either.
        assert!(finish(&x, &w, &[1; 32], &[2; 32], &[0u8]).is_err());
        assert!(finish(&x, &w, &[1; 32], &[2; 32], &[]).is_err());
    }

    #[test]
    fn wrong_password_breaks_confirmation() {
        let salt = b"0123456789abcdef";
        let w = derive_w(b"right", salt, 100).unwrap();
        let w_bad = derive_w(b"wrong", salt, 100).unwrap();
        let x = random_scalar().unwrap();
        let y = random_scalar().unwrap();
        let n = decode_point(&N_COMPRESSED).unwrap();
        let dev_share = encode_point(&(ProjectivePoint::GENERATOR * y + n * w.w0));
        let good = finish(&x, &w, &[1; 32], &[2; 32], &dev_share).unwrap();
        let bad = finish(&x, &w_bad, &[1; 32], &[2; 32], &dev_share).unwrap();
        assert_ne!(good.expected_dev_confirm, bad.expected_dev_confirm);
        assert_ne!(good.user_confirm, bad.user_confirm);
    }

    #[test]
    fn verify_rejects_wrong_or_short_confirm() {
        let w = derive_w(b"pw", b"salt-salt-salt", 10).unwrap();
        let x = random_scalar().unwrap();
        let n = decode_point(&N_COMPRESSED).unwrap();
        let dev_share = encode_point(&(ProjectivePoint::GENERATOR * scalar_from_u64(5) + n * w.w0));
        let hs = finish(&x, &w, &[1; 32], &[2; 32], &dev_share).unwrap();
        assert!(!hs.verify_dev_confirm(&[0u8; 32]));
        assert!(!hs.verify_dev_confirm(&hs.expected_dev_confirm[..16]));
    }
}
