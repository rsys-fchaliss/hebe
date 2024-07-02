mod cli;
mod config;
mod db;
mod trivy;

use std::io::Write;
use std::path::Path;
use std::{fs::File, str::FromStr};

use anyhow::{bail, Context, Result};
use clap::Parser;
use cli::CLIWrapper;
use dialoguer::{theme::ColorfulTheme, Select};
use docx_rs::{Docx, Paragraph, Run};
use reqwest::Client as ReqwestClient;
use serde_json::json;
use spinoff::{spinners, Color, Spinner};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{filter::LevelFilter, EnvFilter, Layer};

fn init_logging(log_level: &String, ansi_color: &bool, json_output: &bool) {
    let mut layers = Vec::new();
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_file(true)
        .with_ansi(*ansi_color)
        .with_line_number(true);

    let fmt_layer = match json_output {
        true => fmt_layer.json().flatten_event(true).boxed(),
        false => fmt_layer.boxed(),
    };
    layers.push(fmt_layer);

    // Filter events with LOG_LEVEL
    let env_filter = if log_level == "INFO" {
        let log_level = match &log_level[..] {
            "warn" => "hebe_launcher=warn,hebe_router=warn",
            "info" => "hebe_launcher=info,hebe_router=info",
            "debug" => "hebe_launcher=debug,hebe_router=debug",
            log_level => log_level,
        };
        EnvFilter::builder()
            .with_default_directive(LevelFilter::INFO.into())
            .parse_lossy(log_level)
    } else {
        EnvFilter::new("info")
    };

    tracing_subscriber::registry()
        .with(env_filter)
        .with(layers)
        .init();
}

#[tokio::main]
async fn main() -> Result<()> {
    let service_settings = config::ServiceConfig::load()?;
    init_logging(
        &service_settings.log.level,
        &service_settings.log.ansi_color,
        &service_settings.log.json_output,
    );
    tracing::info!("config: {:?}", service_settings);
    let database = db::Database::new(&service_settings.database.url).unwrap();

    let cli = CLIWrapper::new(database);
    cli.execute();

    Ok(())
}
