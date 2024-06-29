mod config;
mod db;
mod trivy;

use std::io::Write;
use std::path::Path;
use std::{fs::File, str::FromStr};

use anyhow::{bail, Context, Result};
use clap::Parser;
use dialoguer::{theme::ColorfulTheme, Select};
use docx_rs::{Docx, Paragraph, Run};
use reqwest::Client as ReqwestClient;
use serde_json::json;
use spinoff::{spinners, Color, Spinner};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{filter::LevelFilter, EnvFilter, Layer};


#[derive(Debug, Parser)]
#[clap(
    name = "Hebe",
    version = "1.0",
    author = "Hebe Team",
    about = "Radisys Vulnerability Assessment Manager",
    after_help = "Vulnerability Manager for details reachout x@radisys.com"
)]

struct Opt {
    #[clap(short, long)]
    input_config_file: String,

    #[clap(
        short,
        long,
        value_enum,
        default_value = "Terminal",
        ignore_case = true
    )]
    output_type: OutputType,

    #[clap(short, long, default_value = "false")]
    verbose: String,

    #[clap(long)]
    sbom: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum OutputType {
    Terminal,
    Text,
    Word,
    Markdown,
    Slack,
}

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
    init_logging(&service_settings.log.level, &service_settings.log.ansi_color, &service_settings.log.json_output);
    tracing::info!("config: {:?}", service_settings);

    let database = db::Database::new(&service_settings.database.url).unwrap();

    let (target, results) = trivy::scan_image(&service_settings.sbom.sbom_path);
    for result in results {
        match result.vulnerabilities {
            Some(vulns) => {
                for vuln in vulns {
                    match database.insert_cve(
                        &vuln.id,
                        &vuln.package_name,
                        &vuln
                            .fixed_version
                            .unwrap_or(String::from_str("NULL").unwrap()),
                    ) {
                        Ok(_) => {}
                        Err(e) => eprintln!("Problem inserting row: {e:?}"),
                    };

                    match database.insert_vuln(&target, &vuln.id, &vuln.installed_version) {
                        Ok(_) => {}
                        Err(e) => eprintln!("Problem inserting row: {e:?}"),
                    };
                }
            }
            None => println!("No vulnerabilities found"),
        }
    }

    Ok(())
}