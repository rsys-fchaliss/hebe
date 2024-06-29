use config::Config;
use serde::{Deserialize, Serialize};
use anyhow::Result;

#[derive(Serialize, Deserialize, Debug)]
pub struct ServiceConfig {
    pub database: Database,
    pub log: Log,
    pub sbom: Sbom,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct Log {
    pub level: String,
    pub json_output: bool,
    pub ansi_color: bool,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct Database {
    pub url: String,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct Sbom{
    pub sbom_path: String,
}

impl ServiceConfig {
    pub fn load() -> Result<Self> {
        let settings_reader = Config::builder()
            .add_source(config::File::with_name("config.toml").required(true))
            .build()?;

        let settings = settings_reader.try_deserialize()?;

        Ok(settings)
    }
}