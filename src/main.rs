mod cli;
mod config;
mod db;
mod logging;
mod trivy;

use anyhow::Result;
use cli::CLIWrapper;

#[tokio::main]
async fn main() -> Result<()> {
    let service_settings = config::ServiceConfig::load()?;
    logging::init_logging(
        &service_settings.log.level,
        &service_settings.log.ansi_color,
        &service_settings.log.json_output,
    );
    // tracing::info!("config: {:?}", service_settings);
    let database = db::Database::new(&service_settings.database.url).unwrap();

    let cli = CLIWrapper::new(database);
    cli.execute();

    Ok(())
}
