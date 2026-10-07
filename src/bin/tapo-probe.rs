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

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(host) = args.first().filter(|a| !a.starts_with("--")) else {
        eprintln!("usage: tapo-probe <device-host> [--credentials-file PATH]");
        std::process::exit(2);
    };
    let path = args
        .iter()
        .position(|a| a == "--credentials-file")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from)
        .unwrap_or_else(default_credentials_path);

    let creds = match Credentials::from_file(&path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("credentials: {e}");
            std::process::exit(2);
        }
    };
    let client = TpapClient::new(ClientConfig::new(host.clone()), creds).expect("client");

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
