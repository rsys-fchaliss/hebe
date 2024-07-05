use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{filter::LevelFilter, EnvFilter, Layer};

pub fn init_logging(log_level: &String, ansi_color: &bool, json_output: &bool) {
    let mut layers = Vec::new();
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_file(true)
        .with_ansi(*ansi_color)
        .with_line_number(true);

    let fmt_layer = match json_output {
        true => fmt_layer.json().flatten_event(true).boxed(),
        false => fmt_layer.boxed(),
    };
    layers.push(fmt_layer);

    // Filter events with LOG_LEVEL
    let env_filter = if log_level == "INFO" {
        let log_level = match &log_level[..] {
            "warn" => "hebe_launcher=warn,hebe_router=warn",
            "info" => "hebe_launcher=info,hebe_router=info",
            "debug" => "hebe_launcher=debug,hebe_router=debug",
            log_level => log_level,
        };
        EnvFilter::builder()
            .with_default_directive(LevelFilter::WARN.into())
            .parse_lossy(log_level)
    } else {
        EnvFilter::new("info")
    };

    tracing_subscriber::registry()
        .with(env_filter)
        .with(layers)
        .init();
}
