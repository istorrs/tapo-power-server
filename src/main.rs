//! tapo-power-server: HTTP power-control server for TPAP Tapo power strips.

use std::{path::PathBuf, sync::Arc};

use clap::Parser;
use tapo_power_server::{
    client::{ClientConfig, TpapClient},
    credentials::Credentials,
    error::TapoError,
    server::{AppState, router},
    strip::Strip,
};

/// Serves one Tapo power strip over the pyhil power-server HTTP contract.
///
/// The TP-Link account password is never taken as a command-line argument:
/// use --credentials-file, or the environment variables named by
/// --email-env / --password-env.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Address to listen on.
    #[arg(long, default_value = "0.0.0.0")]
    host: String,
    /// Port to listen on.
    #[arg(long)]
    port: u16,
    /// Name of the environment variable holding the bearer token to require.
    /// Unset means the API is open.
    #[arg(long, value_name = "ENVVAR")]
    token_env: Option<String>,
    /// Address of the Tapo device.
    #[arg(long, value_name = "IP")]
    device_host: String,
    /// HTTP port of the Tapo device.
    #[arg(long, default_value_t = 80)]
    device_port: u16,
    /// File with TAPO_EMAIL= and TAPO_PASSWORD= lines (must be mode 0600).
    #[arg(long, value_name = "PATH", conflicts_with_all = ["email_env", "password_env"])]
    credentials_file: Option<PathBuf>,
    /// Environment variable holding the account email.
    #[arg(long, value_name = "ENVVAR", default_value = "TAPO_EMAIL")]
    email_env: String,
    /// Environment variable holding the account password.
    #[arg(long, value_name = "ENVVAR", default_value = "TAPO_PASSWORD")]
    password_env: String,
}

async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let credentials = match &args.credentials_file {
        Some(path) => Credentials::from_file(path),
        None => Credentials::from_env(&args.email_env, &args.password_env),
    }
    .unwrap_or_else(|e| {
        eprintln!("error: {e}");
        std::process::exit(2);
    });

    let token = args
        .token_env
        .as_deref()
        .map(|var| match std::env::var(var) {
            Ok(t) if !t.is_empty() => Arc::new(t),
            _ => {
                eprintln!("error: --token-env names `{var}`, which is unset or empty");
                std::process::exit(2);
            }
        });

    let mut config = ClientConfig::new(args.device_host.clone());
    config.port = args.device_port;
    let strip = Arc::new(Strip::new(
        TpapClient::new(config, credentials).unwrap_or_else(|e| {
            eprintln!("error: {e}");
            std::process::exit(2);
        }),
    ));

    let listener = tokio::net::TcpListener::bind((args.host.as_str(), args.port))
        .await
        .unwrap_or_else(|e| {
            eprintln!("error: cannot listen on {}:{}: {e}", args.host, args.port);
            std::process::exit(1);
        });
    eprintln!(
        "listening on {} (auth {})",
        listener.local_addr().map_or_else(
            |_| format!("{}:{}", args.host, args.port),
            |a| a.to_string()
        ),
        if token.is_some() { "required" } else { "off" }
    );

    // Try one login up front, in the background so the server (and /health)
    // is available immediately even if the device is slow or offline. A
    // rejected login does NOT exit: a supervisor restarting the process would
    // retry the login and could lock the device out. The server stays up and
    // answers device routes with errors until it is restarted by hand.
    let initial = strip.clone();
    let (device_host, device_port) = (args.device_host.clone(), args.device_port);
    tokio::spawn(async move {
        match initial.client().connect().await {
            Ok(()) => eprintln!("connected to {device_host}:{device_port}"),
            Err(e @ TapoError::Authentication(_)) => eprintln!(
                "ERROR: {e}\nERROR: device routes will fail until the credentials are fixed and the server is restarted"
            ),
            Err(e) => eprintln!("warning: initial connection failed ({e}); will retry on demand"),
        }
    });

    let state = AppState::new(strip, token);
    let tracker = state.tracker.clone();
    let app = router(state);
    let served = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await;

    // HTTP has stopped, but device operations whose client already left (a
    // sequence mid-hold, say) must finish: dropping the runtime now would abort
    // them and could leave an outlet in an intermediate state.
    tracker.close();
    if !tracker.is_empty() {
        eprintln!(
            "waiting for {} device operation(s) to finish",
            tracker.len()
        );
    }
    tracker.wait().await;

    if let Err(e) = served {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
