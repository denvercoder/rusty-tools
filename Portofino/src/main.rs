use clap::{Parser, ValueEnum};
use std::{
    collections::HashMap,
    env,
    io::{self, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream},
    path::PathBuf,
    process,
    str::FromStr,
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc::{self, Sender},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

/// Portofino — a multithreaded TCP port scanner.
///
/// Run with no arguments for an interactive wizard, or pass flags below for
/// non-interactive/scriptable use (e.g. from the Rusty Tools dashboard).
#[derive(Parser)]
#[command(name = "portofino", about = "A multithreaded TCP port scanner")]
struct Cli {
    /// Number of threads to use, shared across all scanned hosts (max 2000)
    #[arg(short = 'n', long, default_value_t = 1)]
    threads: u16,

    /// Target: a single IP, a range (10.0.0.1-50), or a CIDR block (10.0.0.0/24)
    #[arg(short, long)]
    target: String,

    /// Which ports to scan
    #[arg(short, long, value_enum, default_value_t = PortMode::All)]
    ports: PortMode,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum PortMode {
    All,
    Common,
}

const MAX: u16 = 65535;

const CONNECT_TIMEOUT: Duration = Duration::from_millis(500);

const MAX_THREADS: u16 = 2000;

fn clamp_threads(threads: u16) -> u16 {
    if threads > MAX_THREADS {
        println!("2000 thread limit");
        MAX_THREADS
    } else {
        threads
    }
}

/// Max hosts allowed in one range/CIDR scan, so a typo like a /8 doesn't
/// silently queue up millions of hosts.
const MAX_HOSTS: u32 = 65536;

/// The most frequently exposed TCP ports, used for the fast "common ports"
/// scan mode instead of sweeping the full 1-65535 range.
const COMMON_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900,
    8080,
];

/// Pulls (host, port) work items from a shared counter over the flattened
/// `targets x ports` space, so every thread stays busy across the whole
/// scan instead of being confined to one host at a time.
fn scan_worker(
    targets: &[IpAddr],
    ports: &[u16],
    next_index: &AtomicU64,
    total: u64,
    tx: &Sender<(IpAddr, u16)>,
    scanned: &AtomicU64,
) {
    loop {
        let idx = next_index.fetch_add(1, Ordering::Relaxed);
        if idx >= total {
            break;
        }

        let ports_len = ports.len() as u64;
        let host_idx = (idx / ports_len) as usize;
        let port = ports[(idx % ports_len) as usize];
        let ip = targets[host_idx];

        let addr = SocketAddr::new(ip, port);
        if TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT).is_ok() {
            tx.send((ip, port)).unwrap();
        }

        scanned.fetch_add(1, Ordering::Relaxed);
    }
}

fn print_progress(scanned: &Arc<AtomicU64>, total: u64) {
    loop {
        let done = scanned.load(Ordering::Relaxed).min(total);
        let percent = (done as f64 / total as f64) * 100.0;
        print!("\rScanning: {}/{} ports ({:.1}%)", done, total, percent);
        io::stdout().flush().unwrap();

        if done >= total {
            println!();
            break;
        }

        thread::sleep(Duration::from_millis(100));
    }
}

fn run(threads: u16, targets: &[IpAddr], ports: &[u16]) {
    let total_work = targets.len() as u64 * ports.len() as u64;
    let targets: Arc<[IpAddr]> = Arc::from(targets);
    let ports: Arc<[u16]> = Arc::from(ports);
    let next_index = Arc::new(AtomicU64::new(0));
    let scanned = Arc::new(AtomicU64::new(0));
    let (tx, rx) = mpsc::channel::<(IpAddr, u16)>();
    let mut handles = vec![];

    let progress_scanned = Arc::clone(&scanned);
    let progress_handle = thread::spawn(move || print_progress(&progress_scanned, total_work));

    for _ in 0..threads {
        let targets_clone = Arc::clone(&targets);
        let ports_clone = Arc::clone(&ports);
        let next_index_clone = Arc::clone(&next_index);
        let scanned_clone = Arc::clone(&scanned);
        let tx_clone = tx.clone();

        let handle = thread::spawn(move || {
            scan_worker(
                &targets_clone,
                &ports_clone,
                &next_index_clone,
                total_work,
                &tx_clone,
                &scanned_clone,
            )
        });

        handles.push(handle);
    }
    for h in handles {
        h.join().unwrap();
    }

    progress_handle.join().unwrap();

    drop(tx);

    let mut open_ports: HashMap<IpAddr, Vec<u16>> = HashMap::new();
    for (ip, port) in rx {
        open_ports.entry(ip).or_default().push(port);
    }

    let multi_host = targets.len() > 1;
    for ip in targets.iter() {
        if multi_host {
            println!("\n{}", ip);
        }
        match open_ports.get(ip) {
            Some(ports) => {
                let mut ports = ports.clone();
                ports.sort_unstable();
                for port in ports {
                    println!("PORT {} is Open", port);
                }
            }
            None => println!("No open ports found on {}", ip),
        }
    }
}

/// Parses a scan target: a single IP, a hyphenated range ("10.0.0.1-50" or
/// "10.0.0.1-10.0.0.50"), or a CIDR block ("10.0.0.0/24"). Network and
/// broadcast addresses are excluded from CIDR blocks of /30 or larger.
fn parse_ip_range(input: &str) -> Result<Vec<IpAddr>, String> {
    let input = input.trim();

    if let Some((base, prefix_str)) = input.split_once('/') {
        let base_ip: Ipv4Addr = base
            .parse()
            .map_err(|_| format!("'{}' is not a valid IPv4 address", base))?;
        let prefix: u32 = prefix_str
            .parse()
            .map_err(|_| format!("'{}' is not a valid CIDR prefix", prefix_str))?;
        if prefix > 32 {
            return Err("CIDR prefix must be between 0 and 32".to_string());
        }

        let host_bits = 32 - prefix;
        if host_bits > 16 {
            return Err(format!(
                "/{} is too large ({} hosts) — use a /16 or smaller",
                prefix,
                1u64 << host_bits
            ));
        }

        let mask: u32 = if prefix == 0 { 0 } else { u32::MAX << host_bits };
        let network = u32::from(base_ip) & mask;
        let broadcast = network | !mask;

        let (start, end) = if host_bits >= 2 {
            (network + 1, broadcast - 1)
        } else {
            (network, broadcast)
        };

        return Ok((start..=end).map(|v| IpAddr::V4(Ipv4Addr::from(v))).collect());
    }

    if let Some((start_str, end_str)) = input.split_once('-') {
        let start_ip: Ipv4Addr = start_str
            .trim()
            .parse()
            .map_err(|_| format!("'{}' is not a valid IPv4 address", start_str.trim()))?;
        let start = u32::from(start_ip);

        let end_str = end_str.trim();
        let end = if let Ok(end_ip) = end_str.parse::<Ipv4Addr>() {
            u32::from(end_ip)
        } else if let Ok(last_octet) = end_str.parse::<u8>() {
            (start & 0xFFFF_FF00) | last_octet as u32
        } else {
            return Err(format!(
                "'{}' is not a valid end of range (expected an IP or a last octet)",
                end_str
            ));
        };

        if end < start {
            return Err("Range end must not be before range start".to_string());
        }
        if end - start + 1 > MAX_HOSTS {
            return Err(format!(
                "Range is too large ({} hosts) — scan {} hosts or fewer at a time",
                end - start + 1,
                MAX_HOSTS
            ));
        }

        return Ok((start..=end).map(|v| IpAddr::V4(Ipv4Addr::from(v))).collect());
    }

    let ip = IpAddr::from_str(input)
        .map_err(|_| format!("'{}' is not a valid IP address, range, or CIDR block", input))?;
    Ok(vec![ip])
}

fn scan_targets(threads: u16, ip_range: &str, ports: &[u16]) {
    let targets = match parse_ip_range(ip_range) {
        Ok(targets) => targets,
        Err(err) => {
            println!("{}", err);
            process::exit(1);
        }
    };

    if targets.len() > 1 {
        println!(
            "Scanning {} hosts ({} ports each) with {} thread(s) shared across all hosts.",
            targets.len(),
            ports.len(),
            threads
        );
    }

    let start = Instant::now();

    run(threads, &targets, ports);

    println!("Ran for {} seconds", start.elapsed().as_secs_f64().round() as u64);
}

fn prompt(question: &str) -> String {
    print!("{}", question);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

fn prompt_threads() -> u16 {
    loop {
        let input = prompt("How many threads would you like to use? ");
        match input.parse::<u16>() {
            Ok(n) if n > 0 => return clamp_threads(n),
            _ => println!("Please enter a whole number greater than 0."),
        }
    }
}

fn prompt_ip_range() -> String {
    prompt("What IP range would you like to scan? (single IP, 10.0.0.1-50, or 10.0.0.0/24): ")
}

fn prompt_port_selection() -> Vec<u16> {
    loop {
        let input = prompt("Scan all ports or look for most common ports? (all/common): ");
        match input.to_lowercase().as_str() {
            "all" | "a" => return (1..=MAX).collect(),
            "common" | "c" => return COMMON_PORTS.to_vec(),
            _ => println!("Please enter 'all' or 'common'."),
        }
    }
}

fn run_interactive() {
    let threads = prompt_threads();
    let ip_range = prompt_ip_range();
    let ports = prompt_port_selection();
    scan_targets(threads, &ip_range, &ports);
}

enum LaunchMode {
    CommandLine,
    Web,
}

fn prompt_launch_mode() -> LaunchMode {
    loop {
        let input = prompt("[C]ommand Line or [I]nteractive? ");
        match input.trim().to_lowercase().chars().next() {
            Some('c') => return LaunchMode::CommandLine,
            Some('i') => return LaunchMode::Web,
            _ => println!("Please enter C or I."),
        }
    }
}

/// Starts the Rusty Tools web dashboard (a sibling crate) and blocks until
/// it's stopped, so its own "listening on ..." message and auto-opened
/// browser tab show up right in this same terminal session.
fn launch_dashboard() {
    let dashboard_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../dashboard");

    println!("Starting the Rusty Tools dashboard...");

    let status = process::Command::new("cargo")
        .args(["run", "--release"])
        .current_dir(&dashboard_dir)
        .status();

    match status {
        Ok(status) if !status.success() => {
            println!("Dashboard exited with {}", status);
        }
        Err(err) => println!("Failed to start the dashboard: {}", err),
        _ => {}
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        match prompt_launch_mode() {
            LaunchMode::CommandLine => run_interactive(),
            LaunchMode::Web => launch_dashboard(),
        }
        return;
    }

    let cli = Cli::parse();
    let threads = clamp_threads(cli.threads);
    let ports: Vec<u16> = match cli.ports {
        PortMode::All => (1..=MAX).collect(),
        PortMode::Common => COMMON_PORTS.to_vec(),
    };

    scan_targets(threads, &cli.target, &ports);
}
