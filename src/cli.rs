use clap::{Parser, Subcommand};
use tabled::Table;

use crate::db;
use crate::trivy;
use std::process::exit;
use std::str::FromStr;

#[derive(Parser)]
#[clap(
    name = "Hebe",
    version = "1.0",
    author = "Hebe Team",
    about = "Radisys Vulnerability Assessment Manager",
    after_help = "Vulnerability Manager for details reachout x@radisys.com"
)]

struct Opt {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Scan {
        #[clap(long)]
        image: String,
    },
    QueryVulnerabilities {
        #[clap(long)]
        image: Option<String>,
        #[clap(long)]
        cve: Option<String>,
        #[clap(long)]
        severity: Option<String>,
    },
    TriageVulnerability {
        #[clap(long)]
        image: String,
        #[clap(long)]
        cve: String,
        #[clap(long)]
        version: String,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum OutputType {
    CSV,
    TEXT,
}

pub struct CLIWrapper {
    database: db::Database,
    app: Opt,
}

impl CLIWrapper {
    pub fn new(database: db::Database) -> Self {
        Self {
            database,
            app: Opt::parse(),
        }
    }

    pub fn execute(&self) -> () {
        match &self.app.command {
            Commands::Scan { image } => self.scan_and_persist(image),
            Commands::QueryVulnerabilities {
                image,
                cve,
                severity,
            } => self.query(image, cve, severity),
            Commands::TriageVulnerability {
                image,
                cve,
                version,
            } => self.triage_vulnerability(image, cve, version),
        }
    }

    fn scan_and_persist(&self, image: &str) {
        let results = trivy::scan_image(image);
        for result in results {
            match result.vulnerabilities {
                Some(vulns) => {
                    for vuln in vulns {
                        match &self.database.insert_cve(
                            &vuln.id,
                            &vuln.package_name,
                            &vuln.fixed_version.unwrap_or(String::from_str("").unwrap()),
                            &vuln.severity,
                        ) {
                            Ok(_) => {}
                            Err(e) => eprintln!("Problem inserting row: {e:?}"),
                        };

                        match &self
                            .database
                            .insert_vuln(image, &vuln.id, &vuln.installed_version)
                        {
                            Ok(_) => {}
                            Err(e) => eprintln!("Problem inserting row: {e:?}"),
                        };
                    }
                }
                None => println!("No vulnerabilities found in {}", result.target),
            }
        }
    }

    fn query(&self, image: &Option<String>, cve: &Option<String>, severity: &Option<String>) {
        if image.is_some() && cve.is_some() {
            eprintln!("Both image and cve are specified, please specify only one.");
            exit(1);
        }

        if image.is_none() && cve.is_none() {
            eprintln!("Neither of image or cve is specified, please specify one.");
            exit(1);
        }

        if image.is_some() {
            let cves = self.database.get_cves(&image.clone().unwrap(), &severity);
            println!("{}", Table::new(cves).to_string());
        }

        if cve.is_some() {
            let targets = self.database.get_targets_with_cve(&cve.clone().unwrap());
            println!("{}", Table::new(targets).to_string());
        }
    }

    fn triage_vulnerability(&self, image: &str, cve: &str, version: &str) {
        match &self.database.triage_vuln(cve, image, version) {
            Ok(_) => {}
            Err(e) => eprintln!("Problem inserting row: {e:?}"),
        };
    }
}
