mod support;

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use support::{
    ensure_client_bin, log_snapshot, pick_tcp_port, pick_udp_port, server_bin_path,
    spawn_accept_loop_target, spawn_server_client_ready, test_cert_and_key, wait_for_log,
    workspace_root, ChildGuard, ClientArgs, LogCapture, ServerArgs,
};

const ENV_ENABLE: &str = "SLIPSTREAM_FLOW_CONTROL_TEST";
const DOMAIN: &str = "test.example.com";

fn assert_log_absent(logs: &LogCapture, needle: &str, duration: Duration) {
    let deadline = Instant::now() + duration;
    while Instant::now() < deadline {
        let snapshot = log_snapshot(logs);
        if snapshot.contains(needle) {
            panic!("unexpected log entry: {}", needle);
        }
        thread::sleep(Duration::from_millis(50));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetMode {
    Blackhole,
    Echo,
}

#[derive(Debug)]
enum TargetEvent {
    Accepted { index: usize, mode: TargetMode },
}

struct FlowControlHarness {
    _server: ChildGuard,
    _client: ChildGuard,
    server_logs: LogCapture,
    client_logs: LogCapture,
    target: support::TargetHarness<TargetEvent>,
    client_addr: SocketAddr,
}

fn setup_flow_control(envs: &[(&str, &str)]) -> Option<FlowControlHarness> {
    if std::env::var(ENV_ENABLE).is_err() {
        eprintln!(
            "skipping flow control e2e test; set {}=1 to enable",
            ENV_ENABLE
        );
        return None;
    }

    let root = workspace_root();
    let client_bin = ensure_client_bin(&root);
    let server_bin = server_bin_path();

    let (cert, key) = test_cert_and_key(&root);

    let dns_port = match pick_udp_port() {
        Ok(port) => port,
        Err(err) => {
            eprintln!("skipping flow control e2e test: {}", err);
            return None;
        }
    };
    let tcp_port = match pick_tcp_port() {
        Ok(port) => port,
        Err(err) => {
            eprintln!("skipping flow control e2e test: {}", err);
            return None;
        }
    };

    let target = match spawn_accept_loop_target(|stream, tx, stop_flag, index| {
        let mode = if index == 0 {
            TargetMode::Blackhole
        } else {
            TargetMode::Echo
        };
        let _ = tx.send(TargetEvent::Accepted { index, mode });
        let stop_conn = Arc::clone(&stop_flag);
        Some(thread::spawn(move || {
            let mut stream = stream;
            let _ = stream.set_nodelay(true);
            match mode {
                TargetMode::Blackhole => {
                    while !stop_conn.load(Ordering::Relaxed) {
                        thread::sleep(Duration::from_millis(100));
                    }
                }
                TargetMode::Echo => {
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
                    let mut buf = [0u8; 4096];
                    while !stop_conn.load(Ordering::Relaxed) {
                        match stream.read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                if stream.write_all(&buf[..n]).is_err() {
                                    break;
                                }
                            }
                            Err(err)
                                if err.kind() == std::io::ErrorKind::TimedOut
                                    || err.kind() == std::io::ErrorKind::WouldBlock =>
                            {
                                continue;
                            }
                            Err(_) => break,
                        }
                    }
                }
            }
        }))
    }) {
        Ok(target) => target,
        Err(err) => {
            eprintln!("skipping flow control e2e test: {}", err);
            return None;
        }
    };

    let support::ServerClientHarness {
        server,
        client,
        server_logs,
        client_logs,
    } = spawn_server_client_ready(
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
            envs,
            rust_log: "info",
            capture_logs: true,
        },
        ClientArgs {
            client_bin: &client_bin,
            dns_port,
            tcp_port,
            domain: DOMAIN,
            cert: Some(&cert),
            keep_alive_interval: Some(0),
            envs,
            rust_log: "debug",
            capture_logs: true,
        },
        "skipping flow control e2e test: server failed to start",
        Duration::from_millis(200),
    )?;

    let client_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, tcp_port));

    Some(FlowControlHarness {
        _server: server,
        _client: client,
        server_logs,
        client_logs,
        target,
        client_addr,
    })
}

fn open_blackhole_stream(
    harness: &FlowControlHarness,
    expected_index: usize,
    send_duration: Duration,
    payload_len: usize,
) -> TcpStream {
    let server_logs = &harness.server_logs;
    let client_logs = &harness.client_logs;
    let target = &harness.target;
    let client_addr = harness.client_addr;
    let mut blocked = TcpStream::connect_timeout(&client_addr, Duration::from_secs(2))
        .expect("connect blocked stream");
    let _ = blocked.set_nodelay(true);
    let _ = blocked.set_write_timeout(Some(Duration::from_millis(200)));

    if !wait_for_log(client_logs, "Accepted TCP stream", Duration::from_secs(5)) {
        let snapshot = log_snapshot(client_logs);
        panic!("client did not accept blocked stream\n{}", snapshot);
    }

    let warmup = vec![0u8; 1024];
    let _ = blocked.write_all(&warmup);

    match target.recv_event(Duration::from_secs(5)) {
        Some(TargetEvent::Accepted { index, mode }) => {
            assert_eq!(index, expected_index, "unexpected target index");
            assert_eq!(mode, TargetMode::Blackhole, "expected blackhole target");
        }
        None => {
            let snapshot = log_snapshot(server_logs);
            panic!("target did not accept blackhole connection\n{}", snapshot);
        }
    }

    let send_deadline = Instant::now() + send_duration;
    let payload = vec![0u8; payload_len];
    while Instant::now() < send_deadline {
        match blocked.write(&payload) {
            Ok(0) => break,
            Ok(_) => continue,
            Err(_) => break,
        }
    }

    blocked
}

#[test]
fn blocked_stream_should_not_stall_other_streams() {
    let Some(harness) = setup_flow_control(&[
        ("SLIPSTREAM_STREAM_QUEUE_MAX_BYTES", "65536"),
        ("SLIPSTREAM_CONN_RESERVE_BYTES", "65536"),
        ("SLIPSTREAM_STREAM_WRITE_BUFFER_BYTES", "8388608"),
    ]) else {
        return;
    };

    let server_logs = &harness.server_logs;
    let client_logs = &harness.client_logs;
    let target = &harness.target;
    let client_addr = harness.client_addr;
    let _blocked = open_blackhole_stream(&harness, 0, Duration::from_secs(3), 32 * 1024);

    let mut echo = TcpStream::connect_timeout(&client_addr, Duration::from_secs(2))
        .expect("connect echo stream");
    let _ = echo.set_nodelay(true);
    let _ = echo.set_read_timeout(Some(Duration::from_millis(200)));

    if !wait_for_log(client_logs, "Accepted TCP stream", Duration::from_secs(5)) {
        let snapshot = log_snapshot(client_logs);
        panic!("client did not accept echo stream\n{}", snapshot);
    }

    let ping = b"slipstream-flow-control";
    echo.write_all(ping).expect("write echo payload");

    match target.recv_event(Duration::from_secs(5)) {
        Some(TargetEvent::Accepted { index, mode }) => {
            assert_eq!(index, 1, "expected second target connection to be index 1");
            assert_eq!(mode, TargetMode::Echo, "expected echo target");
        }
        None => {
            let snapshot = log_snapshot(server_logs);
            panic!("target did not accept echo connection\n{}", snapshot);
        }
    }

    let mut buf = vec![0u8; ping.len()];
    let mut read_total = 0usize;
    let deadline = Instant::now() + Duration::from_secs(10);
    while read_total < buf.len() && Instant::now() < deadline {
        match echo.read(&mut buf[read_total..]) {
            Ok(0) => break,
            Ok(n) => read_total += n,
            Err(err)
                if err.kind() == std::io::ErrorKind::WouldBlock
                    || err.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(err) => panic!("read echo payload failed: {}", err),
        }
    }
    if read_total != buf.len() {
        let client_snapshot = log_snapshot(client_logs);
        let server_snapshot = log_snapshot(server_logs);
        panic!(
            "echo payload incomplete (got {} of {})\nclient logs:\n{}\nserver logs:\n{}",
            read_total,
            buf.len(),
            client_snapshot,
            server_snapshot
        );
    }
    if buf.as_slice() != ping {
        let client_snapshot = log_snapshot(client_logs);
        let server_snapshot = log_snapshot(server_logs);
        panic!(
            "echo payload mismatch\nclient logs:\n{}\nserver logs:\n{}",
            client_snapshot, server_snapshot
        );
    }
}

#[test]
fn single_stream_slow_transfer_should_not_abort() {
    let Some(harness) = setup_flow_control(&[
        ("SLIPSTREAM_STREAM_QUEUE_MAX_BYTES", "32768"),
        ("SLIPSTREAM_CONN_RESERVE_BYTES", "16384"),
        ("SLIPSTREAM_STREAM_WRITE_BUFFER_BYTES", "8388608"),
    ]) else {
        return;
    };

    let server_logs = &harness.server_logs;
    let client_logs = &harness.client_logs;
    let _blocked = open_blackhole_stream(&harness, 0, Duration::from_secs(2), 64 * 1024);

    assert_log_absent(server_logs, "queued_bytes", Duration::from_secs(1));
    assert_log_absent(client_logs, "reset event", Duration::from_secs(1));
}
