#![allow(dead_code)]

use std::collections::VecDeque;
use std::io::{self, BufRead, BufReader, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const LOG_CAPACITY: usize = 200;

pub struct ChildGuard {
    child: Child,
}

impl ChildGuard {
    pub fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    pub fn has_exited(&mut self) -> bool {
        match self.child.try_wait() {
            Ok(Some(_)) => true,
            Ok(None) => false,
            Err(_) => true,
        }
    }
}

pub fn terminate_process(child: &mut ChildGuard, timeout: Duration) {
    #[cfg(unix)]
    unsafe {
        let _ = libc::kill(child.child.id() as i32, libc::SIGTERM);
    }
    #[cfg(windows)]
    {
        let _ = child.child.kill();
    }
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if child.has_exited() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    child.kill();
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.kill();
    }
}

pub struct LogCapture {
    pub rx: Receiver<String>,
    pub lines: Arc<Mutex<VecDeque<String>>>,
}

pub struct TargetHarness<E> {
    pub addr: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
    conn_handles: Arc<Mutex<Vec<thread::JoinHandle<()>>>>,
    rx: Receiver<E>,
    wake_on_drop: bool,
}

impl<E> TargetHarness<E> {
    pub fn recv_event(&self, timeout: Duration) -> Option<E> {
        self.rx.recv_timeout(timeout).ok()
    }
}

impl<E> Drop for TargetHarness<E> {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if self.wake_on_drop {
            let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(200));
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        if let Ok(mut handles) = self.conn_handles.lock() {
            for handle in handles.drain(..) {
                let _ = handle.join();
            }
        }
    }
}

pub struct ServerArgs<'a> {
    pub server_bin: &'a Path,
    pub dns_listen_host: Option<&'a str>,
    pub dns_port: u16,
    pub target_address: &'a str,
    pub domains: &'a [&'a str],
    pub cert: &'a Path,
    pub key: &'a Path,
    pub reset_seed_path: Option<&'a Path>,
    pub fallback_addr: Option<SocketAddr>,
    pub idle_timeout_seconds: Option<u64>,
    pub envs: &'a [(&'a str, &'a str)],
    pub rust_log: &'a str,
    pub capture_logs: bool,
}

pub struct ClientArgs<'a> {
    pub client_bin: &'a Path,
    pub dns_port: u16,
    pub tcp_port: u16,
    pub domain: &'a str,
    pub cert: Option<&'a Path>,
    pub keep_alive_interval: Option<u16>,
    pub envs: &'a [(&'a str, &'a str)],
    pub rust_log: &'a str,
    pub capture_logs: bool,
}

pub struct ServerClientHarness {
    pub server: ChildGuard,
    pub client: ChildGuard,
    pub server_logs: LogCapture,
    pub client_logs: LogCapture,
}

pub fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

pub fn server_bin_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_slipstream-server"))
}

pub fn client_bin_path(root: &Path) -> PathBuf {
    let mut path = root.join("target").join("debug").join("slipstream-client");
    if cfg!(windows) {
        path.set_extension("exe");
    }
    path
}

pub fn ensure_client_bin(root: &Path) -> PathBuf {
    let path = client_bin_path(root);
    let status = Command::new("cargo")
        .arg("build")
        .arg("-p")
        .arg("slipstream-client")
        .current_dir(root)
        .status()
        .expect("failed to invoke cargo build for slipstream-client");
    assert!(status.success(), "cargo build -p slipstream-client failed");
    path
}

pub fn test_cert_and_key(root: &Path) -> (PathBuf, PathBuf) {
    let cert = root.join("fixtures/certs/cert.pem");
    let key = root.join("fixtures/certs/key.pem");
    assert!(cert.exists(), "missing fixtures/certs/cert.pem");
    assert!(key.exists(), "missing fixtures/certs/key.pem");
    (cert, key)
}

pub fn pick_udp_port() -> io::Result<u16> {
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    Ok(socket.local_addr()?.port())
}

pub fn pick_tcp_port() -> io::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

pub fn spawn_server(args: ServerArgs<'_>) -> (ChildGuard, Option<LogCapture>) {
    let mut cmd = Command::new(args.server_bin);
    if let Some(host) = args.dns_listen_host {
        cmd.arg("--dns-listen-host").arg(host);
    }
    cmd.arg("--dns-listen-port")
        .arg(args.dns_port.to_string())
        .arg("--target-address")
        .arg(args.target_address);
    for domain in args.domains {
        cmd.arg("--domain").arg(domain);
    }
    if let Some(seed_path) = args.reset_seed_path {
        cmd.arg("--reset-seed").arg(seed_path);
    }
    if let Some(fallback_addr) = args.fallback_addr {
        cmd.arg("--fallback").arg(fallback_addr.to_string());
    }
    if let Some(idle_timeout) = args.idle_timeout_seconds {
        cmd.arg("--idle-timeout-seconds")
            .arg(idle_timeout.to_string());
    }
    for (key, value) in args.envs {
        cmd.env(key, value);
    }
    cmd.arg("--cert")
        .arg(args.cert)
        .arg("--key")
        .arg(args.key)
        .env("RUST_LOG", args.rust_log);
    spawn_process(&mut cmd, args.capture_logs, "slipstream-server")
}

pub fn spawn_client(args: ClientArgs<'_>) -> (ChildGuard, Option<LogCapture>) {
    let mut cmd = Command::new(args.client_bin);
    cmd.arg("--tcp-listen-port")
        .arg(args.tcp_port.to_string())
        .arg("--resolver")
        .arg(format!("127.0.0.1:{}", args.dns_port))
        .arg("--domain")
        .arg(args.domain);
    if let Some(cert) = args.cert {
        cmd.arg("--cert").arg(cert);
    }
    if let Some(interval) = args.keep_alive_interval {
        cmd.arg("--keep-alive-interval").arg(interval.to_string());
    }
    for (key, value) in args.envs {
        cmd.env(key, value);
    }
    cmd.env("RUST_LOG", args.rust_log);
    spawn_process(&mut cmd, args.capture_logs, "slipstream-client")
}

pub fn spawn_server_client_ready(
    server_args: ServerArgs<'_>,
    client_args: ClientArgs<'_>,
    server_fail_message: &str,
    server_start_delay: Duration,
) -> Option<ServerClientHarness> {
    let (mut server, server_logs) = spawn_server(server_args);
    let server_logs = server_logs.expect("server logs");
    if server_start_delay > Duration::from_millis(0) {
        thread::sleep(server_start_delay);
    }
    if server.has_exited() {
        eprintln!("{}", server_fail_message);
        return None;
    }

    let (client, client_logs) = spawn_client(client_args);
    let client_logs = client_logs.expect("client logs");
    if !wait_for_log(
        &client_logs,
        "Listening on TCP port",
        Duration::from_secs(5),
    ) {
        let snapshot = log_snapshot(&client_logs);
        panic!("client did not start listening\n{}", snapshot);
    }
    if !wait_for_log(&client_logs, "Connection ready", Duration::from_secs(10)) {
        let snapshot = log_snapshot(&client_logs);
        panic!("client did not become ready\n{}", snapshot);
    }

    Some(ServerClientHarness {
        server,
        client,
        server_logs,
        client_logs,
    })
}

pub fn log_snapshot(logs: &LogCapture) -> String {
    let buffer = logs.lines.lock().expect("lock log buffer");
    if buffer.is_empty() {
        return "<no logs captured>".to_string();
    }
    buffer.iter().cloned().collect::<Vec<_>>().join("\n")
}

pub fn wait_for_log(logs: &LogCapture, needle: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        let now = Instant::now();
        if now >= deadline {
            return false;
        }
        let remaining = deadline.saturating_duration_since(now);
        match logs.rx.recv_timeout(remaining) {
            Ok(line) => {
                if line.contains(needle) {
                    return true;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => return false,
            Err(mpsc::RecvTimeoutError::Disconnected) => return false,
        }
    }
}

pub fn wait_for_any_log(logs: &LogCapture, needles: &[&str], timeout: Duration) -> Option<String> {
    let deadline = Instant::now() + timeout;
    loop {
        let now = Instant::now();
        if now >= deadline {
            return None;
        }
        let remaining = deadline.saturating_duration_since(now);
        match logs.rx.recv_timeout(remaining) {
            Ok(line) => {
                if needles.iter().any(|needle| line.contains(needle)) {
                    return Some(line);
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => return None,
            Err(mpsc::RecvTimeoutError::Disconnected) => return None,
        }
    }
}

pub fn wait_for_log_since(
    logs: &LogCapture,
    needle: &str,
    start: Instant,
    timeout: Duration,
) -> Option<Duration> {
    let deadline = start + timeout;
    loop {
        let now = Instant::now();
        if now >= deadline {
            return None;
        }
        let remaining = deadline.saturating_duration_since(now);
        match logs.rx.recv_timeout(remaining) {
            Ok(line) => {
                if line.contains(needle) {
                    return Some(Instant::now().saturating_duration_since(start));
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => return None,
            Err(mpsc::RecvTimeoutError::Disconnected) => return None,
        }
    }
}

pub fn poke_client(port: u16, timeout: Duration) -> bool {
    poke_client_with_payload(port, timeout, b"ping")
}

pub fn poke_client_with_payload(port: u16, timeout: Duration, payload: &[u8]) -> bool {
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match TcpStream::connect_timeout(&addr, Duration::from_millis(200)) {
            Ok(mut stream) => {
                let _ = stream.set_nodelay(true);
                let _ = stream.write_all(payload);
                return true;
            }
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::ConnectionRefused
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                thread::sleep(Duration::from_millis(50));
            }
            Err(_) => {
                thread::sleep(Duration::from_millis(50));
            }
        }
    }
    false
}

pub fn spawn_single_target<E, F>(
    on_accept_error: Option<E>,
    handler: F,
) -> io::Result<TargetHarness<E>>
where
    E: Send + 'static,
    F: FnOnce(TcpStream, Sender<E>, Arc<AtomicBool>) -> Option<thread::JoinHandle<()>>
        + Send
        + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let (tx, rx) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_flag = Arc::clone(&stop);
    let conn_handles: Arc<Mutex<Vec<thread::JoinHandle<()>>>> = Arc::new(Mutex::new(Vec::new()));
    let conn_handles_clone = Arc::clone(&conn_handles);

    let handle = thread::spawn(move || {
        let accept = listener.accept();
        if stop_flag.load(Ordering::Relaxed) {
            return;
        }
        match accept {
            Ok((stream, _)) => {
                if let Some(join) = handler(stream, tx, stop_flag) {
                    if let Ok(mut handles) = conn_handles_clone.lock() {
                        handles.push(join);
                    }
                }
            }
            Err(_) => {
                if let Some(event) = on_accept_error {
                    let _ = tx.send(event);
                }
            }
        }
    });

    Ok(TargetHarness {
        addr,
        stop,
        handle: Some(handle),
        conn_handles,
        rx,
        wake_on_drop: true,
    })
}

pub fn spawn_accept_loop_target<E, F>(handler: F) -> io::Result<TargetHarness<E>>
where
    E: Send + 'static,
    F: FnMut(TcpStream, Sender<E>, Arc<AtomicBool>, usize) -> Option<thread::JoinHandle<()>>
        + Send
        + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?;
    let (tx, rx) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_flag = Arc::clone(&stop);
    let conn_handles: Arc<Mutex<Vec<thread::JoinHandle<()>>>> = Arc::new(Mutex::new(Vec::new()));
    let conn_handles_clone = Arc::clone(&conn_handles);

    let handle = thread::spawn(move || {
        let mut index = 0usize;
        let mut handler = handler;
        while !stop_flag.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => {
                    if let Some(join) = handler(stream, tx.clone(), Arc::clone(&stop_flag), index) {
                        if let Ok(mut handles) = conn_handles_clone.lock() {
                            handles.push(join);
                        }
                    }
                    index = index.saturating_add(1);
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    Ok(TargetHarness {
        addr,
        stop,
        handle: Some(handle),
        conn_handles,
        rx,
        wake_on_drop: false,
    })
}

fn spawn_log_reader<R: std::io::Read + Send + 'static>(
    reader: R,
    tx: Sender<String>,
    lines: Arc<Mutex<VecDeque<String>>>,
    source: String,
) {
    thread::spawn(move || {
        let reader = BufReader::new(reader);
        for line in reader.lines() {
            let line = match line {
                Ok(line) => line,
                Err(_) => break,
            };
            let tagged = format!("{}: {}", source, line);
            let _ = tx.send(tagged.clone());
            if let Ok(mut buffer) = lines.lock() {
                if buffer.len() == LOG_CAPACITY {
                    buffer.pop_front();
                }
                buffer.push_back(tagged);
            }
        }
    });
}

fn spawn_process(
    cmd: &mut Command,
    capture_logs: bool,
    name: &str,
) -> (ChildGuard, Option<LogCapture>) {
    if capture_logs {
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    } else {
        cmd.stdout(Stdio::null()).stderr(Stdio::null());
    }
    let mut child = cmd.spawn().expect("start process");
    if !capture_logs {
        return (ChildGuard { child }, None);
    }

    let (tx, rx) = mpsc::channel();
    let lines = Arc::new(Mutex::new(VecDeque::new()));
    if let Some(stdout) = child.stdout.take() {
        spawn_log_reader(
            stdout,
            tx.clone(),
            Arc::clone(&lines),
            format!("{}:stdout", name),
        );
    }
    if let Some(stderr) = child.stderr.take() {
        spawn_log_reader(stderr, tx, Arc::clone(&lines), format!("{}:stderr", name));
    }

    (ChildGuard { child }, Some(LogCapture { rx, lines }))
}
