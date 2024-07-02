use clap::{Parser, Subcommand};
use tabled::Table;

use crate::db;
use crate::trivy;
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
        image: String,
    },
    QueryVulnerabilities {
        #[clap(long)]
        image: Option<String>,
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
            Commands::QueryVulnerabilities { image } => self.query(image),
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
                            &vuln
                                .fixed_version
                                .unwrap_or(String::from_str("NULL").unwrap()),
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

    fn query(&self, image: &Option<String>) {
        if image.is_some() {
            let cves = self.database.get_cves(&image.clone().unwrap());
            println!("{}", Table::new(cves).to_string());
        }
    }
}
