use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{
        sse::{Event, KeepAlive, Sse},
        Html, IntoResponse,
    },
    routing::{get, post},
    Router,
};
use std::{
    collections::HashMap,
    convert::Infallible,
    path::PathBuf,
    process::Stdio,
    sync::{Arc, Mutex as StdMutex},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
    sync::{
        mpsc::{self, UnboundedSender},
        Notify,
    },
};
use tokio_stream::{wrappers::UnboundedReceiverStream, Stream, StreamExt};

/// Local-only: the dashboard ALWAYS binds loopback (127.0.0.1) and can never be
/// pointed at a public interface — it launches active scans/captures on demand,
/// so it must not be reachable off this machine. Only the PORT is configurable,
/// via the `RUSTYTOOLZ_PORT` env var (default 80, so `http://rustytoolz.local`
/// works with a hosts alias).
const DEFAULT_PORT: u16 = 80;

/// The stop signal for each tool's currently running job, if any, keyed by
/// tool name ("portofino", "pppp", ...). Only one job per tool runs at a
/// time from the UI (its Run button is disabled while one is in flight), but
/// different tools can run concurrently, so each gets its own slot.
type RunState = Arc<StdMutex<HashMap<&'static str, Arc<Notify>>>>;

#[tokio::main]
async fn main() {
    let run_state: RunState = Arc::new(StdMutex::new(HashMap::new()));

    let app = Router::new()
        .route("/", get(index))
        .route("/style.css", get(style))
        .route("/panel.js", get(panel_js))
        .route("/portofino", get(portofino_page))
        .route("/portofino/run", get(run_portofino))
        .route("/portofino/stop", post(stop_portofino))
        .route("/pppp", get(pppp_page))
        .route("/pppp/interfaces", get(pppp_interfaces))
        .route("/pppp/run", get(run_pppp))
        .route("/pppp/stop", post(stop_pppp))
        .route("/oneforthehoney", get(honey_page))
        .route("/oneforthehoney/run", get(run_honey))
        .route("/oneforthehoney/stop", post(stop_honey))
        .route("/bunyan", get(bunyan_page))
        .route("/bunyan/run", get(run_bunyan))
        .route("/bunyan/stop", post(stop_bunyan))
        .route("/feefifofim", get(fim_page))
        .route("/feefifofim/run", get(run_fim))
        .route("/feefifofim/stop", post(stop_fim))
        .route("/hardhat", get(hardhat_page))
        .route("/hardhat/run", get(run_hardhat))
        .route("/hardhat/stop", post(stop_hardhat))
        .route("/fafo", get(fafo_page))
        .route("/fafo/run", get(run_fafo))
        .route("/fafo/stop", post(stop_fafo))
        .route("/flushot", get(flushot_page))
        .route("/flushot/run", get(run_flushot))
        .route("/flushot/stop", post(stop_flushot))
        .route("/flushot/info", get(flushot_info))
        .route("/flushot/decrypt", get(run_flushot_decrypt))
        .route("/humptydumpty", get(humptydumpty_page))
        .route("/humptydumpty/run", get(run_humptydumpty))
        .route("/humptydumpty/stop", post(stop_humptydumpty))
        .with_state(run_state);

    let port: u16 = std::env::var("RUSTYTOOLZ_PORT")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(DEFAULT_PORT);
    // Host is fixed to loopback on purpose — only the port is configurable.
    let addr = format!("127.0.0.1:{port}");

    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("Could not bind {addr}: {e}");
            eprintln!("Port 80 needs privilege on Linux/macOS (the Linux installer grants it via setcap) and must be free on Windows.");
            eprintln!("To use a high port instead:  RUSTYTOOLZ_PORT=7878 cargo run -p dashboard --release");
            std::process::exit(1);
        }
    };
    let url = format!("http://{addr}/");
    println!("Rusty Toolz dashboard running at {url}");
    let _ = webbrowser::open(&url);

    axum::serve(listener, app).await.unwrap();
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

async fn style() -> impl IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "text/css")],
        include_str!("../static/style.css"),
    )
}

async fn panel_js() -> impl IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "text/javascript")],
        include_str!("../static/panel.js"),
    )
}

async fn portofino_page() -> Html<&'static str> {
    Html(include_str!("../static/portofino.html"))
}

async fn pppp_page() -> Html<&'static str> {
    Html(include_str!("../static/pppp.html"))
}

async fn honey_page() -> Html<&'static str> {
    Html(include_str!("../static/oneforthehoney.html"))
}

async fn bunyan_page() -> Html<&'static str> {
    Html(include_str!("../static/bunyan.html"))
}

async fn fim_page() -> Html<&'static str> {
    Html(include_str!("../static/feefifofim.html"))
}

async fn hardhat_page() -> Html<&'static str> {
    Html(include_str!("../static/hardhat.html"))
}

async fn fafo_page() -> Html<&'static str> {
    Html(include_str!("../static/fafo.html"))
}

async fn flushot_page() -> Html<&'static str> {
    Html(include_str!("../static/flushot.html"))
}

async fn humptydumpty_page() -> Html<&'static str> {
    Html(include_str!("../static/humptydumpty.html"))
}

/// Absolute path to a sibling crate directory, resolved at compile time from
/// this crate's own manifest dir so it works regardless of the directory the
/// dashboard binary happens to be launched from.
fn crate_dir(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join(name)
}

/// The compiled binary for a sibling crate, shared at the workspace root's
/// `target/` (not `<crate>/target/`, since each is a workspace member).
fn crate_binary(name: &str) -> PathBuf {
    // EXE_SUFFIX is ".exe" on Windows and "" everywhere else, so the same code
    // resolves the built binary on any platform (FAFO is cross-platform).
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../target/release")
        .join(format!("{name}{}", std::env::consts::EXE_SUFFIX))
}

/// Builds `crate_dir/crate_binary` quietly, then runs it with `args`,
/// streaming its combined stdout/stderr back as SSE events. Cancellable at
/// either stage via the per-tool `Notify` registered under `tool_key` in
/// `run_state` — a POST to the matching `/stop` route kills the build or the
/// running process, whichever is in flight.
async fn run_tool(
    run_state: RunState,
    tool_key: &'static str,
    display_name: &'static str,
    dir: PathBuf,
    binary: PathBuf,
    args: Vec<String>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let (tx, rx) = mpsc::unbounded_channel::<String>();

    let stop = Arc::new(Notify::new());
    // If a run for this tool is already active — e.g. started from another
    // browser tab, or the dashboard's own auto-opened window — signal it to
    // stop before we overwrite its slot. Otherwise that first process is
    // orphaned: the slot now points at the new run, so the Stop button can
    // never reach the old one and it keeps running forever. This keeps exactly
    // one live process per tool, which matters most for FAFO (it runs until
    // stopped, unlike the tools that finish on their own).
    if let Some(prev) = run_state.lock().unwrap().insert(tool_key, stop.clone()) {
        prev.notify_one();
    }

    tokio::spawn(async move {
        // Build quietly first — the UI already shows the parameters the user
        // picked, so cargo's own compile/echo noise would just be redundant
        // here. Only surface output if the build actually fails.
        let build = tokio::select! {
            biased;
            _ = stop.notified() => {
                let _ = tx.send("Stopped.".to_string());
                clear_slot(&run_state, tool_key, &stop);
                let _ = tx.send("__DONE__".to_string());
                return;
            }
            result = Command::new("cargo").args(["build", "--release"]).current_dir(dir).output() => result,
        };

        match build {
            Ok(output) if !output.status.success() => {
                let _ = tx.send(format!("Failed to build {}:", display_name));
                for line in String::from_utf8_lossy(&output.stderr).lines() {
                    let _ = tx.send(line.to_string());
                }
                clear_slot(&run_state, tool_key, &stop);
                let _ = tx.send("__DONE__".to_string());
                return;
            }
            Err(err) => {
                let _ = tx.send(format!("Failed to build {}: {}", display_name, err));
                clear_slot(&run_state, tool_key, &stop);
                let _ = tx.send("__DONE__".to_string());
                return;
            }
            Ok(_) => {}
        }

        let mut child = match Command::new(binary)
            .args(&args)
            .kill_on_drop(true)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(child) => child,
            Err(err) => {
                let _ = tx.send(format!("Failed to start {}: {}", display_name, err));
                clear_slot(&run_state, tool_key, &stop);
                let _ = tx.send("__DONE__".to_string());
                return;
            }
        };

        let stdout = child.stdout.take().expect("stdout piped");
        let stderr = child.stderr.take().expect("stderr piped");

        let out_task = tokio::spawn(stream_chunks(stdout, tx.clone()));
        let err_task = tokio::spawn(stream_chunks(stderr, tx.clone()));

        tokio::select! {
            biased;
            _ = stop.notified() => {
                let _ = tx.send("Stopped.".to_string());
                let _ = child.start_kill();
            }
            _ = child.wait() => {}
        }

        let _ = out_task.await;
        let _ = err_task.await;

        clear_slot(&run_state, tool_key, &stop);
        let _ = tx.send("__DONE__".to_string());
    });

    let stream = UnboundedReceiverStream::new(rx).map(|chunk| {
        if chunk == "__DONE__" {
            Ok(Event::default().event("done").data(""))
        } else {
            Ok(Event::default().data(chunk))
        }
    });

    Sse::new(stream).keep_alive(KeepAlive::default())
}

/// Removes `tool_key`'s slot, but only if it still points at *this* run —
/// avoids a finishing run clobbering a different, newer run's stop signal.
fn clear_slot(run_state: &RunState, tool_key: &'static str, stop: &Arc<Notify>) {
    let mut guard = run_state.lock().unwrap();
    if guard.get(tool_key).is_some_and(|current| Arc::ptr_eq(current, stop)) {
        guard.remove(tool_key);
    }
}

fn stop_tool(run_state: RunState, tool_key: &str) -> impl IntoResponse {
    match run_state.lock().unwrap().remove(tool_key) {
        Some(stop) => {
            stop.notify_one();
            (StatusCode::OK, "stopping")
        }
        None => (StatusCode::OK, "nothing running"),
    }
}

async fn run_portofino(
    State(run_state): State<RunState>,
    Query(params): Query<HashMap<String, String>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let threads = params.get("threads").cloned().unwrap_or_else(|| "1".into());
    let target = params.get("target").cloned().unwrap_or_default();
    let ports = params.get("ports").cloned().unwrap_or_else(|| "all".into());

    let args = vec![
        "--threads".to_string(),
        threads,
        "--target".to_string(),
        target,
        "--ports".to_string(),
        ports,
    ];

    run_tool(
        run_state,
        "portofino",
        "Portofino",
        crate_dir("Portofino"),
        crate_binary("Portofino"),
        args,
    )
    .await
}

async fn stop_portofino(State(run_state): State<RunState>) -> impl IntoResponse {
    stop_tool(run_state, "portofino")
}

async fn run_pppp(
    State(run_state): State<RunState>,
    Query(params): Query<HashMap<String, String>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let interface = params.get("interface").cloned().unwrap_or_default();
    let mut args = vec![interface.clone()];

    let non_empty = |key: &str| params.get(key).map(|v| v.trim()).filter(|v| !v.is_empty());

    if let Some(protocol) = non_empty("protocol").filter(|p| *p != "all") {
        args.push("--protocol".to_string());
        args.push(protocol.to_string());
    }
    if let Some(port) = non_empty("port") {
        args.push("--port".to_string());
        args.push(port.to_string());
    }
    if let Some(host) = non_empty("host") {
        args.push("--host".to_string());
        args.push(host.to_string());
    }
    if params.get("save_pcap").map(String::as_str) == Some("1") {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let filename = format!("{}-{}.pcap", interface, ts);
        // Absolute, regardless of the dashboard's own working directory, so
        // it always lands in the gitignored captures/ dir next to the tool.
        let path = crate_dir("PickAPeckOfPacketParsers").join("captures").join(filename);
        args.push("--pcap-out".to_string());
        args.push(path.to_string_lossy().into_owned());
    }

    run_tool(
        run_state,
        "pppp",
        "PickAPeckOfPacketParsers",
        crate_dir("PickAPeckOfPacketParsers"),
        crate_binary("PickAPeckOfPacketParsers"),
        args,
    )
    .await
}

async fn stop_pppp(State(run_state): State<RunState>) -> impl IntoResponse {
    stop_tool(run_state, "pppp")
}

async fn run_honey(
    State(run_state): State<RunState>,
    Query(params): Query<HashMap<String, String>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let non_empty = |key: &str| params.get(key).map(|v| v.trim()).filter(|v| !v.is_empty());

    let mut args = Vec::new();
    if let Some(bind) = non_empty("bind") {
        args.push("--bind".to_string());
        args.push(bind.to_string());
    }
    if let Some(ports) = non_empty("ports") {
        args.push("--ports".to_string());
        args.push(ports.to_string());
    }
    if params.get("no_banner").map(String::as_str) == Some("1") {
        args.push("--no-banner".to_string());
    }

    run_tool(
        run_state,
        "oneforthehoney",
        "OneForTheHoney",
        crate_dir("OneForTheHoney"),
        crate_binary("OneForTheHoney"),
        args,
    )
    .await
}

async fn stop_honey(State(run_state): State<RunState>) -> impl IntoResponse {
    stop_tool(run_state, "oneforthehoney")
}

async fn run_bunyan(
    State(run_state): State<RunState>,
    Query(params): Query<HashMap<String, String>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let mut args = Vec::new();
    if let Some(file) = params.get("file").map(|v| v.trim()).filter(|v| !v.is_empty()) {
        args.push("--file".to_string());
        args.push(file.to_string());
    }

    run_tool(
        run_state,
        "bunyan",
        "Bunyan",
        crate_dir("Bunyan"),
        crate_binary("Bunyan"),
        args,
    )
    .await
}

async fn stop_bunyan(State(run_state): State<RunState>) -> impl IntoResponse {
    stop_tool(run_state, "bunyan")
}

async fn run_fim(
    State(run_state): State<RunState>,
    Query(params): Query<HashMap<String, String>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let non_empty = |key: &str| params.get(key).map(|v| v.trim()).filter(|v| !v.is_empty());

    let path = non_empty("path").unwrap_or_default().to_string();

    let baseline = match non_empty("baseline") {
        Some(baseline) => baseline.to_string(),
        None => {
            let sanitized = path.replace('/', "_");
            crate_dir("FeeFiFoFIM")
                .join("baselines")
                .join(format!("{}.json", sanitized))
                .to_string_lossy()
                .into_owned()
        }
    };

    let mut args = vec![path, "--baseline".to_string(), baseline];

    if params.get("init").map(String::as_str) == Some("1") {
        args.push("--init".to_string());
    }
    if let Some(watch) = non_empty("watch") {
        args.push("--watch".to_string());
        args.push(watch.to_string());
    }

    run_tool(
        run_state,
        "feefifofim",
        "FeeFiFoFIM",
        crate_dir("FeeFiFoFIM"),
        crate_binary("FeeFiFoFIM"),
        args,
    )
    .await
}

async fn stop_fim(State(run_state): State<RunState>) -> impl IntoResponse {
    stop_tool(run_state, "feefifofim")
}

async fn run_hardhat(State(run_state): State<RunState>) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    run_tool(run_state, "hardhat", "HardHat", crate_dir("HardHat"), crate_binary("HardHat"), Vec::new()).await
}

async fn stop_hardhat(State(run_state): State<RunState>) -> impl IntoResponse {
    stop_tool(run_state, "hardhat")
}

async fn run_fafo(
    State(run_state): State<RunState>,
    Query(params): Query<HashMap<String, String>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let non_empty = |key: &str| params.get(key).map(|v| v.trim()).filter(|v| !v.is_empty());

    let mut args = Vec::new();

    // Extra targets (e.g. a host-only gateway IP), separated by commas or
    // whitespace. Empty means "use FAFO's built-in public-DNS defaults".
    if let Some(targets) = non_empty("targets") {
        for target in targets.split(|c: char| c == ',' || c.is_whitespace()).filter(|s| !s.is_empty()) {
            args.push("--target".to_string());
            args.push(target.to_string());
        }
    }
    if let Some(interval) = non_empty("interval_ms") {
        args.push("--interval-ms".to_string());
        args.push(interval.to_string());
    }
    if let Some(timeout) = non_empty("timeout_ms") {
        args.push("--timeout-ms".to_string());
        args.push(timeout.to_string());
    }
    // The dashboard already shows its own modal + browser notification, so let
    // the user suppress the redundant native Windows popup if they want.
    if params.get("no_popup").map(String::as_str) == Some("1") {
        args.push("--no-popup".to_string());
    }

    run_tool(
        run_state,
        "fafo",
        "FuckAroundFindOut",
        crate_dir("FuckAroundFindOut"),
        crate_binary("FuckAroundFindOut"),
        args,
    )
    .await
}

async fn stop_fafo(State(run_state): State<RunState>) -> impl IntoResponse {
    stop_tool(run_state, "fafo")
}

async fn run_flushot(
    State(run_state): State<RunState>,
    Query(params): Query<HashMap<String, String>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    // The vault lives beside the tool, in a gitignored dir. All blobs (and the
    // key file) land here.
    let vault = flushot_vault_dir();

    let mut args = vec![
        "--vault".to_string(),
        vault.to_string_lossy().into_owned(),
        "fetch".to_string(),
    ];
    // URLs arrive newline-separated in a single param (avoids repeated-key
    // handling, and keeps each URL properly encoded). Blank lines are dropped.
    if let Some(urls) = params.get("urls") {
        for url in urls.split('\n').map(|s| s.trim()).filter(|s| !s.is_empty()) {
            args.push(url.to_string());
        }
    }

    run_tool(
        run_state,
        "flushot",
        "FluShot",
        crate_dir("FluShot"),
        crate_binary("FluShot"),
        args,
    )
    .await
}

async fn stop_flushot(State(run_state): State<RunState>) -> impl IntoResponse {
    stop_tool(run_state, "flushot")
}

async fn run_humptydumpty(
    State(run_state): State<RunState>,
    Query(params): Query<HashMap<String, String>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let mut args = Vec::new();
    if let Some(file) = params.get("file").map(|v| v.trim()).filter(|v| !v.is_empty()) {
        args.push(file.to_string());
    }
    if params.get("strings").map(String::as_str) == Some("1") {
        args.push("--strings".to_string());
    }

    run_tool(
        run_state,
        "humptydumpty",
        "HumptyDumpty",
        crate_dir("HumptyDumpty"),
        crate_binary("HumptyDumpty"),
        args,
    )
    .await
}

async fn stop_humptydumpty(State(run_state): State<RunState>) -> impl IntoResponse {
    stop_tool(run_state, "humptydumpty")
}

/// FluShot's vault directory, as a clean absolute path (no `..` segment) for
/// display and for handing to the tool.
fn flushot_vault_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(|root| root.join("FluShot").join("vault"))
        .unwrap_or_else(|| crate_dir("FluShot").join("vault"))
}

/// Where decrypted plaintext is written by default. Live malware lands here, so
/// this is only meant to be used inside the analysis VM.
fn flushot_decrypted_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(|root| root.join("FluShot").join("decrypted"))
        .unwrap_or_else(|| crate_dir("FluShot").join("decrypted"))
}

/// Minimal JSON string escaping — enough for Windows paths and filenames.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// One call the FluShot page uses to fill the vault/output banners and the
/// decrypt tab's list of available blobs.
async fn flushot_info() -> impl IntoResponse {
    let vault = flushot_vault_dir();
    let decrypted = flushot_decrypted_dir();

    let mut blobs: Vec<String> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&vault) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "enc") {
                if let Some(name) = path.file_name() {
                    blobs.push(name.to_string_lossy().into_owned());
                }
            }
        }
    }
    blobs.sort();

    let blobs_json = blobs
        .iter()
        .map(|b| format!("\"{}\"", json_escape(b)))
        .collect::<Vec<_>>()
        .join(",");
    let body = format!(
        "{{\"vault\":\"{}\",\"decrypted\":\"{}\",\"blobs\":[{}]}}",
        json_escape(&vault.to_string_lossy()),
        json_escape(&decrypted.to_string_lossy()),
        blobs_json
    );

    ([(axum::http::header::CONTENT_TYPE, "application/json")], body)
}

async fn run_flushot_decrypt(
    State(run_state): State<RunState>,
    Query(params): Query<HashMap<String, String>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let vault = flushot_vault_dir();
    let out = params
        .get("out")
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(flushot_decrypted_dir);

    let mut args = vec![
        "--vault".to_string(),
        vault.to_string_lossy().into_owned(),
        "open".to_string(),
    ];
    // Blob filenames arrive newline-separated; join each to the vault, guarding
    // against path traversal by keeping only the file-name component.
    if let Some(blobs) = params.get("blobs") {
        for blob in blobs.split('\n').map(|s| s.trim()).filter(|s| !s.is_empty()) {
            if let Some(name) = std::path::Path::new(blob).file_name() {
                args.push(vault.join(name).to_string_lossy().into_owned());
            }
        }
    }
    args.push("--out".to_string());
    args.push(out.to_string_lossy().into_owned());

    run_tool(
        run_state,
        "flushot",
        "FluShot",
        crate_dir("FluShot"),
        crate_binary("FluShot"),
        args,
    )
    .await
}

/// Network interface names, read straight from `/sys/class/net` (no
/// privileges needed just to list them) so the PPPP form can offer a
/// dropdown instead of making someone guess their interface name.
async fn pppp_interfaces() -> impl IntoResponse {
    let mut names = Vec::new();

    if let Ok(mut entries) = tokio::fs::read_dir("/sys/class/net").await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            if let Some(name) = entry.file_name().to_str() {
                names.push(name.to_string());
            }
        }
    }
    names.sort();

    (
        [(axum::http::header::CONTENT_TYPE, "text/plain")],
        names.join("\n"),
    )
}

/// Reads raw bytes and splits on `\n` OR `\r`, so in-place (`\r`-only)
/// progress updates arrive as separate SSE events instead of being buffered
/// up as one giant line until the tool finishes.
async fn stream_chunks<R: AsyncRead + Unpin>(mut reader: R, tx: UnboundedSender<String>) {
    let mut buf = [0u8; 1024];
    let mut current = Vec::new();

    loop {
        match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                for &byte in &buf[..n] {
                    if byte == b'\n' || byte == b'\r' {
                        if !current.is_empty() {
                            let _ = tx.send(String::from_utf8_lossy(&current).into_owned());
                            current.clear();
                        }
                    } else {
                        current.push(byte);
                    }
                }
            }
        }
    }

    if !current.is_empty() {
        let _ = tx.send(String::from_utf8_lossy(&current).into_owned());
    }
}
