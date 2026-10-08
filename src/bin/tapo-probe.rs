//! Read-only probe: logs in once and prints a safe subset of device info.
//! Never sends a state-changing command.
//!
//! Usage: tapo-probe <device-host> [--credentials-file PATH]

use std::path::PathBuf;

use serde_json::Value;
use tapo_power_server::{
    client::{ClientConfig, TpapClient},
    credentials::Credentials,
};

fn default_credentials_path() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default();
    home.join(".config/tapo-power-server/credentials")
}

const USAGE: &str = "usage: tapo-probe <device-host> [--credentials-file PATH]";

struct Options {
    host: String,
    credentials: PathBuf,
}

/// Strict parsing: an option that needs a value but has none, an unknown
/// option, or a stray argument is an error. Silently falling back to the
/// default credentials file could submit unintended credentials and use up a
/// login attempt on a device that locks out.
fn parse_args(args: &[String]) -> Result<Options, String> {
    let (mut host, mut credentials) = (None, None);
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--credentials-file" => {
                let value = it
                    .next()
                    .filter(|v| !v.starts_with("--"))
                    .ok_or("--credentials-file needs a path")?;
                if credentials.replace(PathBuf::from(value)).is_some() {
                    return Err("--credentials-file given twice".into());
                }
            }
            flag if flag.starts_with("--") => return Err(format!("unknown option {flag}")),
            positional => {
                if host.replace(positional.to_string()).is_some() {
                    return Err("only one device host may be given".into());
                }
            }
        }
    }
    Ok(Options {
        host: host.ok_or("a device host is required")?,
        credentials: credentials.unwrap_or_else(default_credentials_path),
    })
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let opts = parse_args(&args).unwrap_or_else(|e| {
        eprintln!("error: {e}\n{USAGE}");
        std::process::exit(2);
    });
    let (host, path) = (opts.host, opts.credentials);

    let creds = match Credentials::from_file(&path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("credentials: {e}");
            std::process::exit(2);
        }
    };
    let client = TpapClient::new(ClientConfig::new(host), creds).expect("client");

    println!("logging in (single attempt)...");
    if let Err(e) = client.connect().await {
        eprintln!("login failed: {} [{}]", e, e.error_type());
        std::process::exit(1);
    }
    println!("session established");

    match client
        .request(&client.envelope("get_device_info", None))
        .await
    {
        Ok(v) => {
            let r = &v["result"];
            for key in ["model", "type", "fw_ver", "hw_ver", "device_on"] {
                if let Some(x) = r.get(key) {
                    println!("  {key}: {x}");
                }
            }
        }
        Err(e) => eprintln!("get_device_info failed: {e}"),
    }
    match client
        .request(&client.envelope("get_child_device_list", None))
        .await
    {
        Ok(v) => {
            let r = &v["result"];
            println!(
                "  result keys: {:?}",
                r.as_object().map(|o| o.keys().collect::<Vec<_>>())
            );
            let list = r["child_device_list"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            println!("  children: {} (sum={})", list.len(), r["sum"]);
            if let Some(first) = list.first() {
                println!(
                    "  child keys: {:?}",
                    first.as_object().map(|o| o.keys().collect::<Vec<_>>())
                );
            }
            for c in &list {
                let get = |k: &str| c.get(k).cloned().unwrap_or(Value::Null);
                println!(
                    "    position={} on={} nickname={} id={}",
                    get("position"),
                    get("device_on"),
                    get("nickname"),
                    get("device_id")
                );
            }
        }
        Err(e) => eprintln!("get_child_device_list failed: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_host_and_optional_credentials_path() {
        let o = parse_args(&args(&["10.0.0.5"])).unwrap();
        assert_eq!(o.host, "10.0.0.5");
        let o = parse_args(&args(&["--credentials-file", "/x/c", "10.0.0.5"])).unwrap();
        assert_eq!(o.credentials, PathBuf::from("/x/c"));
    }

    #[test]
    fn rejects_missing_values_and_strays() {
        for bad in [
            &["10.0.0.5", "--credentials-file"][..],
            &["--credentials-file", "--other", "10.0.0.5"],
            &["--credentials-file"],
            &["10.0.0.5", "--bogus"],
            &["10.0.0.5", "10.0.0.6"],
            &[
                "--credentials-file",
                "a",
                "--credentials-file",
                "b",
                "10.0.0.5",
            ],
            &[],
        ] {
            assert!(parse_args(&args(bad)).is_err(), "{bad:?}");
        }
    }
}
