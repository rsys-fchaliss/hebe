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

pub fn scan_image(sbom_path: &str) -> (String, Vec<TrivyResult>) {
    let sbom: SBOM = serde_json::from_str(&fs::read_to_string(sbom_path).unwrap())
        .expect("Failed to parse SBOM");

    let image_name = sbom.packages.get(0).unwrap().name.clone();

    let output = Command::new("trivy")
        .arg("sbom")
        .arg("-f")
        .arg("json")
        .arg(sbom_path)
        .output()
        .expect("Failed to execute Trivy");

    if output.status.success() {
        let output: TrivyOutput =
            serde_json::from_slice(&output.stdout).expect("Failed to parse Trivy JSON output");
        return (image_name, output.results);
    } else {
        eprintln!(
            "Trivy scan failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return (image_name, vec![]);
    }
}
