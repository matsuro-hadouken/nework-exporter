use base64::{engine::general_purpose, Engine};
use clap::Parser;
use hyper::{Body, Request, Response, Server, StatusCode};
use hyper::service::{make_service_fn, service_fn};
use serde::Deserialize;
use serde_yaml;
use std::convert::Infallible;
use std::fs;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::{task, time::sleep};
use std::process::Command;

#[derive(Debug, Clone)]
struct MetricsCache {
    pub data: String,
}

impl MetricsCache {
    fn new() -> Self {
        Self { data: String::new() }
    }
}

// Command line arguments
#[derive(Parser, Debug)]
#[command(version, about="Network Prometheus Exporter")]
struct Cli {
    /// Path to configuration file (YAML)
    #[arg(long)]
    config: String,
}

#[derive(Debug, Deserialize)]
struct Config {
    host: String,
    port: u16,
    user: String,
    password: String,
}

fn read_file_to_string(path: &str) -> Option<String> {
    fs::read_to_string(path).ok()
}

fn run_command(cmd: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(cmd).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).to_string())
}

// NIC stats from /sys/class/net/$NIC/statistics
fn nic_stats_output(nic: &str) -> Vec<String> {
    let mut lines = vec![];
    let path = format!("/sys/class/net/{}/statistics", nic);
    let dir = fs::read_dir(&path);
    if let Ok(dir_iter) = dir {
        for entry in dir_iter {
            if let Ok(entry) = entry {
                let f = entry.file_name();
                let metric_name = f.to_string_lossy().to_string();
                let val_path = format!("{}/{}", path, metric_name);
                if let Some(val_str) = read_file_to_string(&val_path) {
                    let val_str = val_str.trim();
                    if val_str.parse::<u64>().is_ok() {
                        lines.push(format!("network_nic_stats{{nic=\"{}\",type=\"{}\"}} {}", nic, metric_name, val_str));
                    }
                }
            }
        }
    }
    lines
}

// Parse /proc/interrupts to produce interrupts_by_cpu and interrupts_by_queue
fn interrupts_output(pattern: &str) -> Vec<String> {
    let mut lines = vec![];
    let content = read_file_to_string("/proc/interrupts").unwrap_or_default();
    let matched_lines: Vec<&str> = content.lines().filter(|l| l.contains(pattern)).collect();
    if matched_lines.is_empty() {
        return lines;
    }

    let mut cpu_sums: Vec<u64> = vec![];
    let mut queue_sums: Vec<(String, u64)> = vec![];

    for line in &matched_lines {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }
        let len = parts.len();
        let cpu_cols = &parts[1..(len-3)];
        for (i, cstr) in cpu_cols.iter().enumerate() {
            let val = cstr.parse::<u64>().unwrap_or(0);
            if i >= cpu_sums.len() {
                cpu_sums.resize(i+1, 0);
            }
            cpu_sums[i] += val;
        }
        let queue_name = parts[len-1];
        let sum_line: u64 = cpu_cols.iter().map(|v| v.parse::<u64>().unwrap_or(0)).sum();
        queue_sums.push((queue_name.to_string(), sum_line));
    }

    for (i, sum) in cpu_sums.iter().enumerate() {
        lines.push(format!("network_interrupts_by_cpu{{cpu=\"{}\"}} {}", i, sum));
    }

    for (queue, qsum) in queue_sums {
        lines.push(format!("network_interrupts_by_queue{{queue=\"{}\"}} {}", queue, qsum));
    }

    lines
}

// Parse /proc/softirqs for NET_RX and NET_TX
fn softirqs_output() -> Vec<String> {
    let mut lines = vec![];
    let content = read_file_to_string("/proc/softirqs").unwrap_or_default();

    for dir in &["NET_RX", "NET_TX"] {
        for l in content.lines() {
            if l.contains(dir) {
                let parts: Vec<&str> = l.split_whitespace().collect();
                if parts.len() < 2 {
                    continue;
                }
                for (i, val_str) in parts.iter().enumerate().skip(1) {
                    if let Ok(val) = val_str.parse::<u64>() {
                        lines.push(format!("network_softirqs{{cpu=\"{}\",direction=\"{}\"}} {}", i-1, dir, val));
                    }
                }
            }
        }
    }

    lines
}

// softnet_stat_output from /proc/net/softnet_stat
fn softnet_stat_output(typ: &str, idx: usize) -> Vec<String> {
    let mut lines = vec![];
    let content = read_file_to_string("/proc/net/softnet_stat").unwrap_or_default();
    let mut sum: u64 = 0;
    for l in content.lines() {
        let parts: Vec<&str> = l.split_whitespace().collect();
        if idx == 0 || idx > parts.len() {
            continue;
        }
        let val_hex = parts[idx-1];
        if let Ok(val) = u64::from_str_radix(val_hex, 16) {
            sum += val;
        }
    }
    lines.push(format!("network_softnet_stat{{type=\"{}\"}} {}", typ, sum));
    lines
}

// Mellanox ethtool stats
fn mellanox_ethtools_prometheus_static(nic: &str) -> Vec<String> {
    let mut lines = vec![];
    let metrics = vec![
        "tx_pci_signal_integrity","rx_pci_signal_integrity","rx_corrected_bits_phy","rx_pcs_symbol_err_phy","module_high_temp",
        "module_bad_shorted","tx_pause_storm_error_events","tx_discards_phy","rx_undersize_pkts_phy","rx_fragments_phy",
        "rx_jabbers_phy","module_bus_stuck","rx_discards_phy","rx_unsupported_op_phy","rx_symbol_err_phy","queue_wake",
        "rx_steer_missed_packets","rx_packets_phy","rx_crc_errors_phy","rx_csum_none","rx_csum_unnecessary","rx_csum_unnecessary_inner",
        "rx_oversize_pkts_sw_drop","rx_buff_alloc_err","rx_xdp_drop","rx_xdp_redirect","rx_xdp_tx_xmit","rx_buffer_passed_thres_phy",
        "rx_oversize_pkts_buffer","rx_out_of_buffer","tx_packets_phy","tx_bytes_phy","tx_csum_none","tx_recover","tx_queue_stopped",
        "tx_queue_dropped","tx_errors_phy","link_down_events_phy","rx_vport_multicast_packets","rx_vport_multicast_bytes",
        "tx_vport_multicast_packets","tx_vport_multicast_bytes","rx_vport_rdma_multicast_packets","rx_vport_rdma_multicast_bytes",
        "tx_vport_rdma_multicast_packets","tx_vport_rdma_multicast_bytes","tx_multicast_phy","rx_multicast_phy"
    ];

    let ethtool_out = run_command("ethtool", &["-S", nic]).unwrap_or_default();
    for m in &metrics {
        let mut val = 0;
        for l in ethtool_out.lines() {
            let line = l.trim();
            if line.starts_with(m) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() == 2 {
                    if let Ok(v) = parts[1].parse::<u64>() {
                        val = v;
                        break;
                    }
                }
            }
        }
        lines.push(format!("network_nic_stats_mlx{{nic=\"{}\",type=\"{}\"}} {}", nic, m, val));
    }

    lines
}

// netstat_output(PATTERN, ARG_IDX)
fn netstat_output(pattern: &str, arg_idx: usize) -> Vec<String> {
    let mut lines = vec![];
    let netstat_out = run_command("netstat", &["-s"]).unwrap_or_default();
    let mut val_opt = None;

    for l in netstat_out.lines() {
        if l.contains(pattern) {
            let parts: Vec<&str> = l.split_whitespace().collect();
            if arg_idx <= parts.len() {
                val_opt = parts.get(arg_idx-1).and_then(|v| v.parse::<u64>().ok());
                if val_opt.is_some() {
                    break;
                }
            }
        }
    }

    if val_opt.is_none() {
        for l in netstat_out.lines() {
            if l.find(pattern).is_some() {
                let line_trimmed = l.trim_start();
                let parts: Vec<&str> = line_trimmed.split_whitespace().collect();
                if arg_idx <= parts.len() {
                    val_opt = parts.get(arg_idx-1).and_then(|v| v.parse::<u64>().ok());
                    if val_opt.is_some() {
                        break;
                    }
                }
            }
        }
    }

    if let Some(val) = val_opt {
        let typ = pattern.replace(' ', "_").replace(":", "");
        lines.push(format!("network_tcp{{type=\"{}\"}} {}", typ, val));
    }

    lines
}

fn collect_metrics() -> String {
    let mut lines = vec![];

    // netstat outputs
    lines.extend(netstat_output("segments retransmitted", 1));
    lines.extend(netstat_output("TCPLostRetransmit", 2));
    lines.extend(netstat_output("fast retransmits", 1));
    lines.extend(netstat_output("TCPSynRetrans", 2));
    lines.extend(netstat_output("bad segments received", 1));
    lines.extend(netstat_output("resets sent$", 1));
    lines.extend(netstat_output("connection resets received$", 1));
    lines.extend(netstat_output("connections reset due to unexpected data$", 1));
    lines.extend(netstat_output("connections reset due to early user close$", 1));

    lines.extend(netstat_output("packet receive errors", 1));
    lines.extend(netstat_output("receive buffer errors", 1));
    lines.extend(netstat_output("send buffer errors", 1));
    lines.extend(netstat_output("packets to unknown port received", 1));
    lines.extend(netstat_output("IgnoredMulti:", 2));
    lines.extend(netstat_output("TCPTimeouts:", 2));
    lines.extend(netstat_output("TCPChallengeACK:", 2));
    lines.extend(netstat_output("fragments dropped after timeout", 1));
    lines.extend(netstat_output("packet reassemblies failed", 1));
    lines.extend(netstat_output("InCEPkts:", 2));
    lines.extend(netstat_output("InBcastPkts:", 2));
    lines.extend(netstat_output("InMcastPkts:", 2));
    lines.extend(netstat_output("InType3:", 2));
    lines.extend(netstat_output("InType11:", 2));

    // Mellanox NICs
    lines.extend(mellanox_ethtools_prometheus_static("enp1s0f0np0"));
    lines.extend(mellanox_ethtools_prometheus_static("enp1s0f1np1"));

    // NIC stats
    lines.extend(nic_stats_output("enp1s0f0np0"));
    lines.extend(nic_stats_output("enp1s0f1np1"));
    lines.extend(nic_stats_output("bond0"));

    // interrupts
    lines.extend(interrupts_output("mlx"));

    // softirqs
    lines.extend(softirqs_output());

    // softnet_stat
    lines.extend(softnet_stat_output("dropped", 2));
    lines.extend(softnet_stat_output("time_squeeze", 3));
    lines.extend(softnet_stat_output("cpu_collision", 9));
    lines.extend(softnet_stat_output("received_rps", 10));
    lines.extend(softnet_stat_output("flow_limit_count", 11));

    lines.join("\n") + "\n"
}

async fn update_cache(cache: Arc<Mutex<MetricsCache>>) {
    loop {
        let new_data = collect_metrics();
        {
            let mut c = cache.lock().await;
            c.data = new_data;
        }
        sleep(Duration::from_secs(30)).await;
    }
}

fn check_basic_auth(req: &Request<Body>, user: &str, password: &str) -> bool {
    let auth_header = match req.headers().get("Authorization") {
        Some(h) => h,
        None => return false,
    };

    if let Ok(header_str) = auth_header.to_str() {
        if header_str.starts_with("Basic ") {
            let encoded = &header_str["Basic ".len()..];
            if let Ok(decoded) = general_purpose::STANDARD.decode(encoded) {
                let creds = String::from_utf8_lossy(&decoded);
                let expected = format!("{}:{}", user, password);
                return creds == expected;
            }
        }
    }

    false
}

async fn serve_metrics(
    req: Request<Body>,
    cache: Arc<Mutex<MetricsCache>>,
    user: String,
    password: String,
) -> Result<Response<Body>, Infallible> {
    if !check_basic_auth(&req, &user, &password) {
        let unauthorized = Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("WWW-Authenticate", r#"Basic realm="Protected Metrics""#)
            .body(Body::from("Unauthorized"))
            .unwrap();
        return Ok(unauthorized);
    }

    if req.uri().path() == "/metrics" {
        let c = cache.lock().await;
        Ok(Response::new(Body::from(c.data.clone())))
    } else {
        let not_found = Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("404 Not Found"))
            .unwrap();
        Ok(not_found)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let config_content = fs::read_to_string(&cli.config)?;
    let config: Config = serde_yaml::from_str(&config_content)?;

    let cache = Arc::new(Mutex::new(MetricsCache::new()));
    let cache_clone = Arc::clone(&cache);

    let user = config.user.clone();
    let password = config.password.clone();

    // Background task: periodically update cache data.
    task::spawn(async move {
        update_cache(cache_clone).await;
    });

    let addr_str = format!("{}:{}", config.host, config.port);
    let addr: SocketAddr = addr_str.parse()?;

    let make_svc = make_service_fn(move |_conn| {
        let cache = Arc::clone(&cache);
        let user = user.clone();
        let password = password.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let cache = Arc::clone(&cache);
                let user = user.clone();
                let password = password.clone();
                async move { serve_metrics(req, cache, user, password).await }
            }))
        }
    });

    println!("Serving metrics on http://{}:{}/metrics (with basic auth)", config.host, config.port);
    Server::bind(&addr).serve(make_svc).await?;
    Ok(())
}
