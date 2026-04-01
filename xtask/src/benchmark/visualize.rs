//! `cargo xtask benchmark visualize` — SVG chart generator.
//!
//! Reads a benchmark report file (YAML or JSON) and produces
//! a grouped bar chart SVG comparing proxy performance.

use clap::Parser;
use praxis_benchmarks::report::BenchmarkReport;

// -----------------------------------------------------------------------------
// CLI Arguments
// -----------------------------------------------------------------------------

/// CLI arguments for `cargo xtask benchmark visualize`.
#[derive(Parser)]
pub struct Args {
    /// Path to the benchmark report file (YAML or JSON).
    pub file: String,

    /// Output directory for SVG files. Defaults to
    /// `target/criterion`.
    #[arg(long)]
    pub output: Option<String>,
}

// -----------------------------------------------------------------------------
// Entry Point
// -----------------------------------------------------------------------------

/// Generate SVG charts from a benchmark report.
///
/// Produces one SVG per metric in the output directory.
#[allow(clippy::print_stdout)]
pub fn run(args: &Args) {
    let report = load_report(&args.file);
    let stem = std::path::Path::new(&args.file)
        .file_stem()
        .map_or("benchmark", |s| s.to_str().unwrap_or("benchmark"));

    let dir = args.output.clone().unwrap_or_else(|| "target/criterion".into());
    std::fs::create_dir_all(&dir).ok();

    render_charts(&report, stem, &dir);
}

// -----------------------------------------------------------------------------
// Report Loading
// -----------------------------------------------------------------------------

/// Load a [`BenchmarkReport`] from YAML or JSON.
///
/// [`BenchmarkReport`]: praxis_benchmarks::report::BenchmarkReport
#[allow(clippy::print_stderr)]
fn load_report(path: &str) -> BenchmarkReport {
    let content = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("failed to read {path}: {e}");
        std::process::exit(1);
    });

    if path.ends_with(".json") {
        serde_json::from_str(&content).unwrap_or_else(|e| {
            eprintln!("failed to parse JSON: {e}");
            std::process::exit(1);
        })
    } else {
        serde_yaml::from_str(&content).unwrap_or_else(|e| {
            eprintln!("failed to parse YAML: {e}");
            std::process::exit(1);
        })
    }
}

// -----------------------------------------------------------------------------
// Data Extraction
// -----------------------------------------------------------------------------

/// Unique scenario names from a report (first-seen order).
fn unique_scenarios(report: &BenchmarkReport) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    report
        .results
        .iter()
        .filter_map(|r| {
            if seen.insert(r.scenario.clone()) {
                Some(r.scenario.clone())
            } else {
                None
            }
        })
        .collect()
}

/// Extract a per-proxy, per-scenario metric matrix.
#[allow(clippy::cast_precision_loss)]
fn extract_matrix<F>(report: &BenchmarkReport, scenarios: &[String], metric: F) -> Vec<Vec<f64>>
where
    F: Fn(&praxis_benchmarks::result::BenchmarkResult) -> f64,
{
    report
        .proxies
        .iter()
        .map(|proxy| {
            scenarios
                .iter()
                .map(|scenario| {
                    report
                        .results
                        .iter()
                        .find(|r| r.proxy == *proxy && r.scenario == *scenario)
                        .and_then(|r| r.median.as_ref())
                        .map_or(0.0, &metric)
                })
                .collect()
        })
        .collect()
}

// -----------------------------------------------------------------------------
// SVG Rendering
// -----------------------------------------------------------------------------

/// Proxy color assignment.
fn proxy_color(name: &str) -> plotters::style::RGBColor {
    match name {
        "praxis" => plotters::style::RGBColor(76, 175, 80),
        "envoy" => plotters::style::RGBColor(33, 150, 243),
        "nginx" => plotters::style::RGBColor(244, 67, 54),
        "haproxy" => plotters::style::RGBColor(156, 39, 176),
        _ => plotters::style::RGBColor(158, 158, 158),
    }
}

/// SVG dimensions.
const SVG_WIDTH: u32 = 1400;
/// Height per panel.
const PANEL_HEIGHT: u32 = 420;
/// Left margin for y-axis labels.
const LEFT_MARGIN: i32 = 90;
/// Top margin per panel (for title).
const TOP_MARGIN: i32 = 35;
/// Bottom margin per panel (for x-axis labels).
const BOTTOM_MARGIN: i32 = 80;

/// Chart definition: metric name, file suffix, title,
/// y-axis label, and extraction function.
struct ChartDef {
    /// File name suffix (e.g. "p99-latency").
    suffix: &'static str,
    /// Chart title.
    title: &'static str,
    /// Y-axis label.
    y_label: &'static str,
    /// Metric extractor.
    extract: fn(&praxis_benchmarks::result::BenchmarkResult) -> f64,
}

/// All charts to render.
const CHARTS: &[ChartDef] = &[
    ChartDef {
        suffix: "p99-latency",
        title: "p99 Latency (ms)  \u{2193} lower is better",
        y_label: "ms",
        extract: |m| m.latency.p99 * 1000.0,
    },
    ChartDef {
        suffix: "throughput",
        title: "Throughput (req/s)  \u{2191} higher is better",
        y_label: "req/s",
        extract: |m| m.throughput.requests_per_sec,
    },
    ChartDef {
        suffix: "min-latency",
        title: "Min Latency (ms)  \u{2193} lower is better",
        y_label: "ms",
        extract: |m| m.latency.min * 1000.0,
    },
    ChartDef {
        suffix: "mean-latency",
        title: "Mean Latency (ms)  \u{2193} lower is better",
        y_label: "ms",
        extract: |m| m.latency.mean * 1000.0,
    },
    ChartDef {
        suffix: "max-latency",
        title: "Max Latency (ms)  \u{2193} lower is better",
        y_label: "ms",
        extract: |m| m.latency.max * 1000.0,
    },
    ChartDef {
        suffix: "data-throughput",
        title: "Data Throughput (MB/s)  \u{2191} higher is better",
        y_label: "MB/s",
        extract: |m| m.throughput.bytes_per_sec / 1_000_000.0,
    },
];

/// Render one SVG per metric into the output directory.
#[allow(clippy::print_stdout, clippy::print_stderr)]
fn render_charts(report: &BenchmarkReport, stem: &str, dir: &str) {
    use plotters::prelude::{IntoDrawingArea, SVGBackend, WHITE};

    let scenarios = unique_scenarios(report);
    if scenarios.is_empty() {
        eprintln!("no scenario data to visualize");
        return;
    }

    for chart in CHARTS {
        let path = format!("{dir}/{stem}-{}.svg", chart.suffix);
        let data = extract_matrix(report, &scenarios, chart.extract);

        let root = SVGBackend::new(&path, (SVG_WIDTH, PANEL_HEIGHT)).into_drawing_area();
        root.fill(&WHITE).unwrap();

        render_panel(&root, chart.title, chart.y_label, &report.proxies, &scenarios, &data);

        root.present().unwrap_or_else(|e| {
            eprintln!("failed to write SVG {path}: {e}");
        });

        println!("  {path}");
    }
}

/// Render a single grouped bar chart panel.
#[allow(clippy::cast_precision_loss)]
fn render_panel(
    area: &plotters::prelude::DrawingArea<plotters::prelude::SVGBackend, plotters::coord::Shift>,
    title: &str,
    y_label: &str,
    proxies: &[String],
    scenarios: &[String],
    bars: &[Vec<f64>],
) {
    use plotters::{
        prelude::{BLACK, ChartBuilder, Rectangle, SeriesLabelPosition, WHITE},
        style::{Color, IntoFont, TextStyle},
    };

    let n_proxies = proxies.len();
    let n_scenarios = scenarios.len();
    let group_width = n_proxies as f64 + 1.0;
    let x_max = n_scenarios as f64 * group_width;

    let max_val = bars.iter().flat_map(|v| v.iter()).copied().fold(0.0_f64, f64::max) * 1.15;
    let max_val = if max_val == 0.0 { 1.0 } else { max_val };

    let mut chart = ChartBuilder::on(area)
        .caption(title, ("sans-serif", 18).into_font())
        .margin_top(TOP_MARGIN as u32)
        .margin_left(10)
        .margin_right(10)
        .x_label_area_size(BOTTOM_MARGIN as u32)
        .y_label_area_size(LEFT_MARGIN as u32)
        .build_cartesian_2d(0.0..x_max, 0.0..max_val)
        .unwrap();

    // Y-axis grid only, no x-axis ticks (we draw labels
    // manually).
    chart
        .configure_mesh()
        .disable_x_mesh()
        .disable_x_axis()
        .y_desc(y_label)
        .y_label_style(("sans-serif", 12).into_font())
        .draw()
        .unwrap();

    // Draw bars.
    for (pi, proxy) in proxies.iter().enumerate() {
        let color = proxy_color(proxy);
        let rects: Vec<_> = (0..n_scenarios)
            .map(|si| {
                let x0 = si as f64 * group_width + pi as f64 + 0.5;
                let x1 = x0 + 0.8;
                let y = bars[pi][si];
                Rectangle::new([(x0, 0.0), (x1, y)], color.filled())
            })
            .collect();

        chart
            .draw_series(rects)
            .unwrap()
            .label(proxy.as_str())
            .legend(move |(x, y)| Rectangle::new([(x, y - 5), (x + 15, y + 5)], color.filled()));
    }

    // Draw x-axis labels centered under each bar group.
    let label_style = TextStyle::from(("sans-serif", 10).into_font()).color(&BLACK);

    for (si, name) in scenarios.iter().enumerate() {
        let center_x = si as f64 * group_width + n_proxies as f64 / 2.0 + 0.5;
        // Shorten long names for readability.
        let short = shorten_scenario(name);
        chart
            .draw_series(std::iter::once(plotters::element::Text::new(
                short,
                (center_x, -max_val * 0.02),
                label_style.clone(),
            )))
            .unwrap();
    }

    chart
        .configure_series_labels()
        .position(SeriesLabelPosition::UpperRight)
        .background_style(WHITE.mix(0.8))
        .border_style(BLACK)
        .label_font(("sans-serif", 12).into_font())
        .draw()
        .unwrap();
}

/// Shorten scenario names for chart labels.
fn shorten_scenario(name: &str) -> String {
    match name {
        "high-concurrency-small-requests" => "small-req".into(),
        "large-payloads" => "large".into(),
        "mixed-payloads" => "mixed".into(),
        "tcp-throughput" => "tcp-thru".into(),
        "tcp-connection-rate" => "tcp-conn".into(),
        other => other.into(),
    }
}
