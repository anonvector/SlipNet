mod support;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use socket2::SockRef;
use support::{
    ensure_client_bin, log_snapshot, pick_tcp_port, pick_udp_port, server_bin_path,
    spawn_server_client_ready, spawn_single_target, test_cert_and_key, wait_for_log,
    workspace_root, ClientArgs, ServerArgs,
};

const DOMAIN: &str = "test.example.com";
#[derive(Debug)]
enum TargetEvent {
    Accepted,
    FirstRead { _bytes: usize },
    Closed,
}

#[test]
fn target_read_error_triggers_client_reset() {
    let root = workspace_root();
    let client_bin = ensure_client_bin(&root);
    let server_bin = server_bin_path();

    let (cert, key) = test_cert_and_key(&root);

    let dns_port = match pick_udp_port() {
        Ok(port) => port,
        Err(err) => {
            eprintln!("skipping target read error e2e test: {}", err);
            return;
        }
    };
    let tcp_port = match pick_tcp_port() {
        Ok(port) => port,
        Err(err) => {
            eprintln!("skipping target read error e2e test: {}", err);
            return;
        }
    };

    let target = match spawn_single_target(
        Some(TargetEvent::Closed),
        move |mut stream, tx, stop_flag| {
            let _ = tx.send(TargetEvent::Accepted);
            let _ = stream.set_nodelay(true);
            let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
            let mut buf = [0u8; 4096];
            let mut total = 0usize;
            loop {
                if stop_flag.load(Ordering::Relaxed) {
                    return None;
                }
                match stream.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        total = total.saturating_add(n);
                        break;
                    }
                    Err(err)
                        if err.kind() == std::io::ErrorKind::Interrupted
                            || err.kind() == std::io::ErrorKind::WouldBlock
                            || err.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        continue;
                    }
                    Err(_) => break,
                }
            }
            let _ = tx.send(TargetEvent::FirstRead { _bytes: total });
            let _ = SockRef::from(&stream).set_linger(Some(Duration::from_secs(0)));
            drop(stream);
            let _ = tx.send(TargetEvent::Closed);
            None
        },
    ) {
        Ok(target) => target,
        Err(err) => {
            eprintln!("skipping target read error e2e test: {}", err);
            return;
        }
    };

    let harness = match spawn_server_client_ready(
        ServerArgs {
            server_bin: &server_bin,
            dns_listen_host: Some("127.0.0.1"),
            dns_port,
            target_address: &format!("127.0.0.1:{}", target.addr.port()),
            domains: &[DOMAIN],
            cert: &cert,
            key: &key,
            reset_seed_path: None,
            fallback_addr: None,
            idle_timeout_seconds: None,
            envs: &[],
            rust_log: "info",
            capture_logs: true,
        },
        ClientArgs {
            client_bin: &client_bin,
            dns_port,
            tcp_port,
            domain: DOMAIN,
            cert: Some(&cert),
            keep_alive_interval: Some(1),
            envs: &[],
            rust_log: "info",
            capture_logs: true,
        },
        "skipping target read error e2e test: server failed to start",
        Duration::from_millis(0),
    ) {
        Some(harness) => harness,
        None => return,
    };
    let support::ServerClientHarness {
        server: _server,
        client: _client,
        server_logs,
        client_logs,
    } = harness;

    let client_addr = SocketAddr::from(([127, 0, 0, 1], tcp_port));
    let mut app = TcpStream::connect_timeout(&client_addr, Duration::from_secs(2))
        .expect("connect client tcp port");
    let _ = app.set_nodelay(true);
    app.write_all(b"first-payload")
        .expect("write first payload");

    let mut saw_accept = false;
    let mut saw_read = false;
    let mut saw_close = false;
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && (!saw_accept || !saw_read || !saw_close) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let Some(event) = target.recv_event(remaining) else {
            break;
        };
        match event {
            TargetEvent::Accepted => saw_accept = true,
            TargetEvent::FirstRead { .. } => saw_read = true,
            TargetEvent::Closed => saw_close = true,
        }
    }
    if !saw_accept || !saw_read || !saw_close {
        let snapshot = log_snapshot(&server_logs);
        panic!(
            "target did not accept/read/close (accept={} read={} close={})\n{}",
            saw_accept, saw_read, saw_close, snapshot
        );
    }

    if !wait_for_log(&server_logs, "target read error", Duration::from_secs(2)) {
        let snapshot = log_snapshot(&server_logs);
        panic!("expected server target read error\n{}", snapshot);
    }

    if !wait_for_log(&client_logs, "reset event=", Duration::from_secs(5)) {
        let client_snapshot = log_snapshot(&client_logs);
        let server_snapshot = log_snapshot(&server_logs);
        panic!(
            "expected client reset event\nclient logs:\n{}\nserver logs:\n{}",
            client_snapshot, server_snapshot
        );
    }
}
