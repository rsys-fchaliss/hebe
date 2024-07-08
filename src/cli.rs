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
        image: Option<String>,
        #[clap(long)]
        sbom: Option<String>,
    },
    QueryVulnerabilities {
        #[clap(long)]
        image: Option<String>,
        #[clap(long)]
        cve: Option<String>,
        #[clap(long)]
        severity: Option<String>,
        #[clap(long)]
        fix_version: Option<String>,
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
            Commands::Scan { image, sbom } => self.scan_and_persist(image, sbom),
            Commands::QueryVulnerabilities {
                image,
                cve,
                severity,
                fix_version,
            } => self.query(image, cve, severity, fix_version),
            Commands::TriageVulnerability {
                image,
                cve,
                version,
            } => self.triage_vulnerability(image, cve, version),
        }
    }

    fn scan_and_persist(&self, image: &Option<String>, sbom_path: &Option<String>) {
        let (image_name, results) = trivy::scan_image(image, sbom_path);
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

                        match &self.database.insert_vuln(
                            &image_name,
                            &vuln.id,
                            &vuln.installed_version,
                        ) {
                            Ok(_) => {}
                            Err(e) => eprintln!("Problem inserting row: {e:?}"),
                        };
                    }

                    self.query(
                        &Some(image_name.clone()),
                        &Option::None,
                        &Option::None,
                        &Option::None,
                    );
                }
                None => println!(),
            }
        }
    }

    fn query(
        &self,
        image: &Option<String>,
        cve: &Option<String>,
        severity: &Option<String>,
        fix_version: &Option<String>,
    ) {
        if image.is_some() && cve.is_some() {
            eprintln!("Both image and cve are specified, please specify only one.");
            exit(1);
        }

        if image.is_none() && cve.is_none() && fix_version.is_none() {
            eprintln!("Neither of image or cve or fix-version is specified, please specify one.");
            exit(1);
        }

        if fix_version.is_some() {
            let cves = self
                .database
                .get_cves_by_fix_version(&image, &fix_version.clone().unwrap());
            println!("{}", Table::new(cves).to_string());

            return;
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

        self.query(
            &Option::Some(String::from_str(image).unwrap()),
            &Option::None,
            &Option::None,
            &Option::Some(String::from_str(version).unwrap()),
        );
    }
}
