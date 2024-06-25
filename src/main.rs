use std::fs::File;
use std::io::Write;
use std::path::Path;

use clap::Parser;
use anyhow::{bail, Context, Result};
use config::{Config, File as ConfigFile};
use serde_json::json;
use spinoff::{spinners, Color, Spinner};
use dialoguer::{theme::ColorfulTheme, Select};
use docx_rs::{Docx, Paragraph, Run};
use reqwest::Client as ReqwestClient;

#[derive(Debug, Parser)]
#[clap(name = "Hebe", version = "1.0", author = "Hebe Team", 
    about = "Radisys Vulnerability Assessment Manager",
    after_help = "Vulnerability Manager for details reachout x@radisys.com",
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

    let db_var = settings
        .get_string("database.database_connection")
        .unwrap_or_default();

    println!("🧙 Welcome to RVAMS");

    if !db_var.is_empty() {
        println!("Configurations: {}", db_var);
    } else {
        bail!("Database connection string is empty");
    } 

    /*
    let mut spinner = Spinner::new(spinners::Dots7, "Connecting to database...", Color::Green);
    println!();
    spinner.update(spinners::Dots7, "Connection successfull...", None);
    */
    Ok(())
}