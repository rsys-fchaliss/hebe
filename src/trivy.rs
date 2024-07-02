use serde::Deserialize;

use std::fs::{self};
use std::process::Command;

#[derive(Deserialize, Debug)]
pub struct SBOM {
    pub packages: Vec<SBOMPackage>,
}

#[derive(Deserialize, Debug)]
pub struct SBOMPackage {
    pub name: String,
}

#[derive(Deserialize, Debug)]
struct TrivyOutput {
    #[serde(rename = "Results")]
    results: Vec<TrivyResult>,
}

#[derive(Deserialize, Debug)]
pub struct TrivyResult {
    #[serde(rename = "Target")]
    pub target: String,
    #[serde(rename = "Vulnerabilities")]
    pub vulnerabilities: Option<Vec<Vulnerability>>,
}

#[derive(Deserialize, Debug)]
pub struct Vulnerability {
    #[serde(rename = "VulnerabilityID")]
    pub id: String,
    #[serde(rename = "PkgName")]
    pub package_name: String,
    #[serde(rename = "InstalledVersion")]
    pub installed_version: String,
    #[serde(rename = "FixedVersion")]
    pub fixed_version: Option<String>,
}

pub fn scan_image(image_name: &str) -> Vec<TrivyResult> {
    let output = Command::new("trivy")
        .arg("image")
        .arg("-f")
        .arg("json")
        .arg(image_name)
        .output()
        .expect("Failed to execute Trivy");

    if output.status.success() {
        let output: TrivyOutput =
            serde_json::from_slice(&output.stdout).expect("Failed to parse Trivy JSON output");
        return output.results;
    } else {
        eprintln!(
            "Trivy scan failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return vec![];
    }
}
