//! Derivation of the PBKDF2 "credentials string" from the device's
//! `extra_crypt` parameters (`userpw` passcode type).

use md5::Md5;
use serde::Deserialize;
use sha1::Sha1;
use sha2::{Digest, Sha256};

#[derive(Debug, Default, Deserialize)]
pub struct ExtraCrypt {
    #[serde(rename = "type")]
    pub kind: Option<String>,
    #[serde(rename = "params")]
    pub params: Option<ExtraCryptParams>,
}

#[derive(Debug, Default, Deserialize)]
pub struct ExtraCryptParams {
    pub passwd_id: Option<i64>,
    pub sha_name: Option<i64>,
    pub sha_salt: Option<String>,
    pub authkey_tmpkey: Option<String>,
    pub authkey_dictionary: Option<String>,
}

pub fn md5_hex(s: &str) -> String {
    hex::encode(Md5::digest(s.as_bytes()))
}

pub fn sha1_hex(s: &str) -> String {
    hex::encode(Sha1::digest(s.as_bytes()))
}

pub fn sha256_hex(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

/// `username/password`, or just the password when the username is blank.
fn user_slash_pass(username: &str, password: &str) -> String {
    if username.trim().is_empty() {
        password.to_string()
    } else {
        format!("{username}/{password}")
    }
}

/// `SHA1hex(MD5hex(username) + "_" + MAC_UPPER_COLON)`; falls back to the
/// plain password when the username is blank or the MAC malformed.
fn sha1_username_mac_shadow(username: &str, mac_no_colon: &str, password: &str) -> String {
    if username.trim().is_empty()
        || mac_no_colon.len() != 12
        || !mac_no_colon.chars().all(|c| c.is_ascii_hexdigit())
    {
        return password.to_string();
    }
    let mac = (0..6)
        .map(|i| mac_no_colon[i * 2..i * 2 + 2].to_ascii_uppercase())
        .collect::<Vec<_>>()
        .join(":");
    sha1_hex(&format!("{}_{}", md5_hex(username), mac))
}

/// `dictionary[(pw[i] ^ key[i]) % len]`, padding the shorter input with 0xBB.
/// Operates on UTF-16 code units like the reference's .NET `char`s.
fn apply_authkey_mask(password: &str, tmp_key: &str, dictionary: &str) -> String {
    let pw: Vec<u16> = password.encode_utf16().collect();
    let key: Vec<u16> = tmp_key.encode_utf16().collect();
    let dict: Vec<u16> = dictionary.encode_utf16().collect();
    let max = pw.len().max(key.len());
    let out: Vec<u16> = (0..max)
        .map(|i| {
            let l = pw.get(i).copied().unwrap_or(0xBB);
            let r = key.get(i).copied().unwrap_or(0xBB);
            dict[usize::from(l ^ r) % dict.len()]
        })
        .collect();
    String::from_utf16_lossy(&out)
}

/// Build the string fed to PBKDF2 as the password.
pub fn build_credentials(
    extra_crypt: Option<&ExtraCrypt>,
    username: &str,
    password: &str,
    mac_no_colon: &str,
) -> String {
    let Some(extra) = extra_crypt else {
        return user_slash_pass(username, password);
    };
    let params = extra.params.as_ref();
    match extra
        .kind
        .as_deref()
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("password_shadow") => match params.and_then(|p| p.passwd_id).unwrap_or(0) {
            2 => sha1_hex(password),
            3 => sha1_username_mac_shadow(username, mac_no_colon, password),
            _ => password.to_string(),
        },
        Some("password_authkey") => {
            let tmp = params
                .and_then(|p| p.authkey_tmpkey.as_deref())
                .unwrap_or("");
            let dict = params
                .and_then(|p| p.authkey_dictionary.as_deref())
                .unwrap_or("");
            if tmp.trim().is_empty() || dict.trim().is_empty() {
                password.to_string()
            } else {
                apply_authkey_mask(password, tmp, dict)
            }
        }
        Some("password_sha_with_salt") => {
            let name = params.and_then(|p| p.sha_name);
            let salt_b64 = params.and_then(|p| p.sha_salt.as_deref()).unwrap_or("");
            let (Some(name), false) = (name, salt_b64.trim().is_empty()) else {
                return password.to_string();
            };
            use base64::Engine;
            let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(salt_b64) else {
                return password.to_string();
            };
            let hint = if name == 0 { "admin" } else { "user" };
            sha256_hex(&format!(
                "{hint}{}{password}",
                String::from_utf8_lossy(&raw)
            ))
        }
        _ => user_slash_pass(username, password),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extra(json: &str) -> ExtraCrypt {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn hashes_match_python_hashlib() {
        assert_eq!(md5_hex("admin"), "21232f297a57a5a743894a0e4a801fc3");
        assert_eq!(sha1_hex("abc"), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn no_extra_crypt_uses_user_slash_pass() {
        assert_eq!(
            build_credentials(None, "u@x", "pw", "AABBCCDDEEFF"),
            "u@x/pw"
        );
        assert_eq!(build_credentials(None, "  ", "pw", "AABBCCDDEEFF"), "pw");
    }

    #[test]
    fn unknown_type_falls_back_to_user_slash_pass() {
        let e = extra(r#"{"type":"something_new","params":{}}"#);
        assert_eq!(build_credentials(Some(&e), "u", "pw", ""), "u/pw");
    }

    #[test]
    fn password_shadow_variants() {
        let id2 = extra(r#"{"type":"password_shadow","params":{"passwd_id":2}}"#);
        assert_eq!(
            build_credentials(Some(&id2), "u", "abc", ""),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        let id3 = extra(r#"{"type":"password_shadow","params":{"passwd_id":3}}"#);
        // Expected value computed with Python: sha1(md5("u") + "_" + "AA:BB:CC:DD:EE:FF").
        assert_eq!(
            build_credentials(Some(&id3), "u", "ignored", "aabbccddeeff"),
            "4626735998c212f74b5871f6dc0a98af1a2275e9"
        );
        // malformed MAC or blank user -> plain password
        assert_eq!(build_credentials(Some(&id3), "u", "pw", "zz"), "pw");
        assert_eq!(
            build_credentials(Some(&id3), "", "pw", "aabbccddeeff"),
            "pw"
        );
        let other = extra(r#"{"type":"password_shadow","params":{"passwd_id":9}}"#);
        assert_eq!(build_credentials(Some(&other), "u", "pw", ""), "pw");
    }

    #[test]
    fn authkey_mask_known_answer() {
        let e = extra(
            r#"{"type":"password_authkey","params":{"authkey_tmpkey":"abcd","authkey_dictionary":"0123456789ABCDEF"}}"#,
        );
        assert_eq!(build_credentials(Some(&e), "u", "secret", ""), "2706EF");
        let missing = extra(r#"{"type":"password_authkey","params":{}}"#);
        assert_eq!(build_credentials(Some(&missing), "u", "pw", ""), "pw");
    }

    #[test]
    fn sha_with_salt_known_answer() {
        // salt "NaCl" base64 = TmFDbA==; name 0 -> "admin"
        let e = extra(
            r#"{"type":"password_sha_with_salt","params":{"sha_name":0,"sha_salt":"TmFDbA=="}}"#,
        );
        assert_eq!(
            build_credentials(Some(&e), "u", "pw", ""),
            sha256_hex("adminNaClpw")
        );
        let user = extra(
            r#"{"type":"password_sha_with_salt","params":{"sha_name":1,"sha_salt":"TmFDbA=="}}"#,
        );
        assert_eq!(
            build_credentials(Some(&user), "u", "pw", ""),
            sha256_hex("userNaClpw")
        );
        let bad =
            extra(r#"{"type":"password_sha_with_salt","params":{"sha_name":0,"sha_salt":"!!"}}"#);
        assert_eq!(build_credentials(Some(&bad), "u", "pw", ""), "pw");
    }
}
