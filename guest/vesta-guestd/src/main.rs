// SPDX-License-Identifier: Apache-2.0
//! vesta-guestd: loads the vesta BPF programs inside a Kata guest and
//! serves the host channel on vsock (ARCHITECTURE §2.2, §2.3).

mod abi;
mod bpf;
mod cgroup;
mod codec;
mod config;
mod ctrl;
mod daemon;
mod events;
mod evt;
mod policy;
mod proto;
mod resolve;
mod server;
mod state;
mod sysinfo;

use std::path::PathBuf;
use std::process::ExitCode;

use config::{Config, LogLevel};

const USAGE: &str = "usage: vesta-guestd [--config PATH] [--check-config] [--version]";

fn init_logging(level: LogLevel) {
    let level = match level {
        LogLevel::Error => tracing::Level::ERROR,
        LogLevel::Warn => tracing::Level::WARN,
        LogLevel::Info => tracing::Level::INFO,
        LogLevel::Debug => tracing::Level::DEBUG,
        LogLevel::Trace => tracing::Level::TRACE,
    };
    // stderr goes to the journal under systemd.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(level)
        .with_target(false)
        .init();
}

fn main() -> ExitCode {
    let mut config_path = PathBuf::from(config::DEFAULT_PATH);
    let mut check_only = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--config" => match args.next() {
                Some(p) => config_path = PathBuf::from(p),
                None => {
                    eprintln!("{USAGE}");
                    return ExitCode::from(2);
                }
            },
            "--check-config" => check_only = true,
            "--version" => {
                println!(
                    "vesta-guestd {} (abi {})",
                    env!("CARGO_PKG_VERSION"),
                    abi::ABI_VERSION
                );
                return ExitCode::SUCCESS;
            }
            _ => {
                eprintln!("{USAGE}");
                return ExitCode::from(2);
            }
        }
    }

    let cfg = match Config::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("vesta-guestd: {e:#}");
            return ExitCode::FAILURE;
        }
    };
    if check_only {
        println!("{}: OK", config_path.display());
        return ExitCode::SUCCESS;
    }
    init_logging(cfg.log_level);

    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!(error = %e, "creating the runtime");
            return ExitCode::FAILURE;
        }
    };
    let local = tokio::task::LocalSet::new();
    match local.block_on(&rt, server::run(cfg)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %format!("{e:#}"), "vesta-guestd failed");
            ExitCode::FAILURE
        }
    }
}
