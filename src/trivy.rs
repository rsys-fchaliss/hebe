use serde::Deserialize;
use spinoff::{spinners, Color, Spinner};
use std::fs;
use std::process::exit;
use std::process::{Command, Output};

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct SBOM {
    pub packages: Vec<SBOMPackage>,
}

#[allow(dead_code)]
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
    #[serde(rename = "Severity")]
    pub severity: String,
}

pub fn scan_image(
    image_name: &Option<String>,
    sbom_path: &Option<String>,
) -> (String, Vec<TrivyResult>) {
    let mut spinner = Spinner::new(spinners::Dots7, "Scanning image ...", Color::Green);

    if image_name.is_none() && sbom_path.is_none() {
        eprintln!("Neither image name or sbom path are specified, please specify one.");
        exit(1);
    }
    if image_name.is_some() && sbom_path.is_some() {
        eprintln!("Both image name and sbom path are specified, please specify only one.");
        exit(1);
    }

    let mut output: Output = Command::new("echo")
        .arg("default")
        .output()
        .expect("Failed to execute default command");

    let mut image = String::new();

    if image_name.is_some() {
        let Some(ref img) = image_name else { todo!() };
        output = Command::new("trivy")
            .arg("image")
            .arg("-f")
            .arg("json")
            .arg(img)
            .output()
            .expect("Failed to execute Trivy");

        image = img.to_string();
    } else if sbom_path.is_some() {
        let Some(ref path) = sbom_path else { todo!() };
        let sbom: SBOM =
            serde_json::from_str(&fs::read_to_string(path).unwrap()).expect("Failed to parse SBOM");

        image = sbom.packages.get(0).unwrap().name.clone();

        output = Command::new("trivy")
            .arg("sbom")
            .arg("-f")
            .arg("json")
            .arg(path)
            .output()
            .expect("Failed to execute Trivy");
    }

    spinner.update(spinners::Dots7, "Image scanning ...Done!", Color::Green);

    if output.status.success() {
        let output: TrivyOutput =
            serde_json::from_slice(&output.stdout).expect("Failed to parse Trivy JSON output");
        return (image, output.results);
    } else {
        eprintln!(
            "Trivy scan failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return (image, vec![]);
    }
}
