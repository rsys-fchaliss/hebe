use std::io::Write;
use std::path::Path;
use std::{fs::File, str::FromStr};

use anyhow::{bail, Context, Result};
use clap::Parser;
use config::{Config, File as ConfigFile};
use dialoguer::{theme::ColorfulTheme, Select};
use docx_rs::{Docx, Paragraph, Run};
use reqwest::Client as ReqwestClient;
use serde_json::json;
use spinoff::{spinners, Color, Spinner};

mod db;
mod trivy;

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

#[tokio::main]
async fn main() -> Result<()> {
    let app = Opt::parse();

    /*
        let settings = Config::builder()
            .add_source(ConfigFile::with_name("./config.toml"))
            .build()?;
    */
    let settings = Config::builder()
        .add_source(ConfigFile::with_name(&app.input_config_file))
        .build()?;

    let database = db::Database::new(&settings.get_string("database.path").unwrap()).unwrap();

    let (target, results) = trivy::scan_image(&app.sbom);
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
