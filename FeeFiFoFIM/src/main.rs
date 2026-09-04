mod baseline;
mod scan;

use baseline::Change;
use clap::Parser;
use std::collections::HashSet;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

/// FeeFiFoFIM — a file integrity monitor.
///
/// `--init` baselines a directory; a plain run checks it against that
/// baseline once; `--watch` keeps checking on an interval.
#[derive(Parser)]
#[command(name = "feefifofim", about = "File integrity monitor")]
struct Cli {
    /// Directory to monitor
    path: PathBuf,

    /// (Re)create the baseline from the current state of `path` and exit
    #[arg(long)]
    init: bool,

    /// Where to store/read the baseline
    #[arg(long, default_value = "fim-baseline.json")]
    baseline: PathBuf,

    /// Keep checking every N seconds instead of a single one-shot check
    #[arg(long)]
    watch: Option<u64>,
}

fn print_change(change: &Change) {
    match change {
        Change::Added { path, size } => println!("ADDED    {}  ({} bytes)", path, size),
        Change::Removed { path } => println!("REMOVED  {}", path),
        Change::Modified { path, old_size, new_size } => {
            println!("MODIFIED {}  ({} -> {} bytes)", path, old_size, new_size)
        }
    }
}

fn run_init(path: &PathBuf, baseline_path: &PathBuf) {
    let snapshot = scan::scan(path);

    let count = snapshot.len();
    if let Err(err) = baseline::save(baseline_path, &snapshot) {
        println!("Failed to write baseline {}: {}", baseline_path.display(), err);
        std::process::exit(1);
    }

    println!("Baseline created: {} files -> {}", count, baseline_path.display());
}

fn run_check_once(path: &PathBuf, baseline_snapshot: &scan::Snapshot) -> Vec<Change> {
    let current = scan::scan(path);
    baseline::diff(baseline_snapshot, &current)
}

fn run_check(path: &PathBuf, baseline_snapshot: &scan::Snapshot) {
    let changes = run_check_once(path, baseline_snapshot);
    let (mut added, mut removed, mut modified) = (0, 0, 0);
    for change in &changes {
        match change {
            Change::Added { .. } => added += 1,
            Change::Removed { .. } => removed += 1,
            Change::Modified { .. } => modified += 1,
        }
        print_change(change);
    }
    let unchanged = baseline_snapshot.len().saturating_sub(removed + modified);
    println!("{} added, {} removed, {} modified, {} unchanged", added, removed, modified, unchanged);
}

fn run_watch(path: &PathBuf, baseline_path: &PathBuf, baseline_snapshot: &scan::Snapshot, interval: u64) {
    println!(
        "Watching {} every {}s against baseline {} (Ctrl+C to stop)",
        path.display(),
        interval,
        baseline_path.display()
    );

    let mut last_reported: HashSet<String> = HashSet::new();
    loop {
        thread::sleep(Duration::from_secs(interval));

        let changes = run_check_once(path, baseline_snapshot);
        let mut still_present = HashSet::new();
        for change in &changes {
            let key = change.key();
            still_present.insert(key.clone());
            if !last_reported.contains(&key) {
                print_change(change);
            }
        }
        last_reported = still_present;
    }
}

fn main() {
    let cli = Cli::parse();

    if cli.init {
        run_init(&cli.path, &cli.baseline);
        return;
    }

    let baseline_snapshot = match baseline::load(&cli.baseline) {
        Ok(snapshot) => snapshot,
        Err(err) => {
            println!(
                "No baseline at {} ({}) — run with --init first",
                cli.baseline.display(),
                err
            );
            std::process::exit(1);
        }
    };

    match cli.watch {
        None => run_check(&cli.path, &baseline_snapshot),
        Some(interval) => run_watch(&cli.path, &cli.baseline, &baseline_snapshot, interval),
    }
}
