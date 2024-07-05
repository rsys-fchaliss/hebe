use anyhow::Result;
use config::Config;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct ServiceConfig {
    pub database: Database,
    pub log: Log,
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

impl ServiceConfig {
    pub fn load() -> Result<Self> {
        let settings_reader = Config::builder()
            .add_source(config::File::with_name("config.toml").required(true))
            .build()?;

        let settings = settings_reader.try_deserialize()?;

        Ok(settings)
    }
}
