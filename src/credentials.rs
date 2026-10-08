//! TP-Link account credentials, loaded from a file or environment variables.
//!
//! Secrets are never accepted as bare CLI arguments, never included in
//! `Debug` output or error messages, and are zeroized on drop.

use std::path::Path;

use zeroize::Zeroizing;

const PLACEHOLDER_EMAIL: &str = "your-tapo-account-email@example.com";
const PLACEHOLDER_PASSWORD: &str = "replace-with-your-tapo-account-password";

#[derive(Debug, thiserror::Error)]
pub enum CredentialsError {
    #[error("cannot read credentials file: {0}")]
    Read(String),
    #[error("credentials file {0} is accessible by other users; run `chmod 600` on it")]
    Permissions(String),
    #[error("credentials file line {0} is not `KEY=VALUE`")]
    Malformed(usize),
    #[error("credentials are missing `{0}`")]
    Missing(&'static str),
    #[error("credentials still contain the placeholder values; edit the file first")]
    Placeholder,
    #[error("environment variable `{0}` is not set")]
    EnvUnset(String),
}

pub struct Credentials {
    email: String,
    password: Zeroizing<String>,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Credentials { <redacted> }")
    }
}

impl Credentials {
    pub fn new(email: String, password: String) -> Result<Self, CredentialsError> {
        if email.is_empty() {
            return Err(CredentialsError::Missing("TAPO_EMAIL"));
        }
        if password.is_empty() {
            return Err(CredentialsError::Missing("TAPO_PASSWORD"));
        }
        if email == PLACEHOLDER_EMAIL || password == PLACEHOLDER_PASSWORD {
            // Guard against burning a login attempt (the device locks out).
            return Err(CredentialsError::Placeholder);
        }
        Ok(Self {
            email,
            password: Zeroizing::new(password),
        })
    }

    pub fn email(&self) -> &str {
        &self.email
    }

    pub fn password(&self) -> &str {
        &self.password
    }

    /// Load `TAPO_EMAIL=` / `TAPO_PASSWORD=` lines from a file. On Unix the
    /// file must not be readable by group or others.
    pub fn from_file(path: &Path) -> Result<Self, CredentialsError> {
        use std::io::Read;
        // Open once and check the permissions of the file actually opened, then
        // read through the same handle: checking the path and then reading it
        // separately would let a replacement slip in between.
        let mut file =
            std::fs::File::open(path).map_err(|e| CredentialsError::Read(e.kind().to_string()))?;
        let meta = file
            .metadata()
            .map_err(|e| CredentialsError::Read(e.kind().to_string()))?;
        if !meta.is_file() {
            return Err(CredentialsError::Read("not a regular file".into()));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o077 != 0 {
                return Err(CredentialsError::Permissions(path.display().to_string()));
            }
        }
        let mut text = Zeroizing::new(String::new());
        file.read_to_string(&mut text)
            .map_err(|e| CredentialsError::Read(e.kind().to_string()))?;
        Self::parse(&text)
    }

    /// Parse `KEY=VALUE` lines. Blank lines and `#` comments are skipped, an
    /// optional leading `export ` is accepted, unknown keys are ignored, and
    /// one pair of matching surrounding quotes is stripped from a value (so a
    /// password that itself starts and ends with a quote must be wrapped in
    /// another pair). Anything else is rejected rather than silently skipped,
    /// because a misread credential costs a login attempt.
    pub fn parse(text: &str) -> Result<Self, CredentialsError> {
        let (mut email, mut password) = (None, None);
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let line = line.strip_prefix("export ").unwrap_or(line);
            let Some((key, value)) = line.split_once('=') else {
                return Err(CredentialsError::Malformed(n + 1));
            };
            let value = unquote(value.trim());
            match key.trim() {
                "TAPO_EMAIL" => email = Some(value.to_string()),
                "TAPO_PASSWORD" => password = Some(value.to_string()),
                _ => {}
            }
        }
        Self::new(
            email.ok_or(CredentialsError::Missing("TAPO_EMAIL"))?,
            password.ok_or(CredentialsError::Missing("TAPO_PASSWORD"))?,
        )
    }

    /// Load from the named environment variables.
    pub fn from_env(email_var: &str, password_var: &str) -> Result<Self, CredentialsError> {
        let email =
            std::env::var(email_var).map_err(|_| CredentialsError::EnvUnset(email_var.into()))?;
        let password = std::env::var(password_var)
            .map_err(|_| CredentialsError::EnvUnset(password_var.into()))?;
        Self::new(email, password)
    }
}

fn unquote(v: &str) -> &str {
    for q in ['"', '\''] {
        if v.len() >= 2 && v.starts_with(q) && v.ends_with(q) {
            return &v[1..v.len() - 1];
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_and_quoted_values() {
        let c = Credentials::parse("# c\nTAPO_EMAIL=a@b.c\nTAPO_PASSWORD=\"p w=1\"\nOTHER=x\n")
            .unwrap();
        assert_eq!(c.email(), "a@b.c");
        assert_eq!(c.password(), "p w=1");
    }

    #[test]
    fn accepts_export_prefix_and_rejects_malformed_lines() {
        let c = Credentials::parse("export TAPO_EMAIL=a@b.c\nexport TAPO_PASSWORD='pw'\n").unwrap();
        assert_eq!((c.email(), c.password()), ("a@b.c", "pw"));
        // A line without `=` is an error that names the line but never its content.
        let err = Credentials::parse("TAPO_EMAIL=a@b.c\nhunter2\nTAPO_PASSWORD=x\n").unwrap_err();
        assert!(matches!(err, CredentialsError::Malformed(2)));
        assert!(!err.to_string().contains("hunter2"));
        // A password that is itself quoted needs a second pair.
        let c = Credentials::parse("TAPO_EMAIL=a@b.c\nTAPO_PASSWORD=\"'q'\"\n").unwrap();
        assert_eq!(c.password(), "'q'");
    }

    #[test]
    fn rejects_placeholders() {
        let text = format!("TAPO_EMAIL={PLACEHOLDER_EMAIL}\nTAPO_PASSWORD=real\n");
        assert!(matches!(
            Credentials::parse(&text),
            Err(CredentialsError::Placeholder)
        ));
        let text = format!("TAPO_EMAIL=a@b.c\nTAPO_PASSWORD={PLACEHOLDER_PASSWORD}\n");
        assert!(matches!(
            Credentials::parse(&text),
            Err(CredentialsError::Placeholder)
        ));
    }

    #[test]
    fn rejects_missing_and_empty() {
        assert!(matches!(
            Credentials::parse("TAPO_EMAIL=a@b.c\n"),
            Err(CredentialsError::Missing("TAPO_PASSWORD"))
        ));
        assert!(matches!(
            Credentials::parse("TAPO_EMAIL=\nTAPO_PASSWORD=x\n"),
            Err(CredentialsError::Missing("TAPO_EMAIL"))
        ));
    }

    #[test]
    fn debug_never_leaks() {
        let c = Credentials::new("a@b.c".into(), "hunter2".into()).unwrap();
        let s = format!("{c:?}");
        assert!(!s.contains("hunter2") && !s.contains("a@b.c"));
    }

    #[test]
    fn a_directory_is_not_a_credentials_file() {
        assert!(matches!(
            Credentials::from_file(&std::env::temp_dir()),
            Err(CredentialsError::Read(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn file_permissions_enforced() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("tapo-cred-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("credentials");
        std::fs::write(&path, "TAPO_EMAIL=a@b.c\nTAPO_PASSWORD=pw\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            Credentials::from_file(&path),
            Err(CredentialsError::Permissions(_))
        ));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(Credentials::from_file(&path).is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
