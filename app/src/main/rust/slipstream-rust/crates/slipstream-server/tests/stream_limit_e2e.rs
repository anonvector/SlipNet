mod support;

use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use support::{
    ensure_client_bin, log_snapshot, pick_tcp_port, pick_udp_port, server_bin_path,
    spawn_accept_loop_target, spawn_server_client_ready, test_cert_and_key, workspace_root,
    ClientArgs, ServerArgs,
};

const DOMAIN: &str = "test.example.com";
const STREAM_LIMIT_FALLBACK: usize = 512;
const STREAM_LIMIT_LOG_NEEDLE: &str = "initial_max_streams_bidir_remote=";
const STREAM_CLOSE_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug)]
enum TargetEvent {
    Accepted,
}

fn parse_stream_limit_line(line: &str) -> Option<usize> {
    let (_, tail) = line.split_once(STREAM_LIMIT_LOG_NEEDLE)?;
    let value = tail.split_whitespace().next()?;
    value.parse::<usize>().ok()
}

fn derive_stream_limit(logs: &support::LogCapture) -> usize {
    let snapshot = log_snapshot(logs);
    if let Some(limit) = snapshot.lines().find_map(parse_stream_limit_line) {
        return limit;
    }

    if let Some(line) =
        support::wait_for_any_log(logs, &[STREAM_LIMIT_LOG_NEEDLE], Duration::from_secs(2))
    {
        if let Some(limit) = parse_stream_limit_line(&line) {
            return limit;
        }
    }

    eprintln!(
        "stream limit not found in client logs; defaulting to {}",
        STREAM_LIMIT_FALLBACK
    );
    STREAM_LIMIT_FALLBACK
}

#[test]
fn stream_limit_reuse_allows_next_stream() {
    let root = workspace_root();
    let client_bin = ensure_client_bin(&root);
    let server_bin = server_bin_path();

    let (cert, key) = test_cert_and_key(&root);

    let dns_port = match pick_udp_port() {
        Ok(port) => port,
        Err(err) => {
            eprintln!("skipping stream limit e2e test: {}", err);
            return;
        }
    };
    let tcp_port = match pick_tcp_port() {
        Ok(port) => port,
        Err(err) => {
            eprintln!("skipping stream limit e2e test: {}", err);
            return;
        }
    };

    let target = match spawn_accept_loop_target(|stream, tx, _stop_flag, _index| {
        let _ = tx.send(TargetEvent::Accepted);
        let _ = stream.set_nodelay(true);
        let _ = stream.shutdown(Shutdown::Both);
        None
    }) {
        Ok(target) => target,
        Err(err) => {
            eprintln!("skipping stream limit e2e test: {}", err);
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
        "skipping stream limit e2e test: server failed to start",
        Duration::from_millis(200),
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

    let stream_limit = derive_stream_limit(&client_logs);
    let client_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, tcp_port));
    for index in 0..=stream_limit {
        let mut stream = TcpStream::connect_timeout(&client_addr, Duration::from_secs(2))
            .unwrap_or_else(|err| panic!("connect stream {}: {}", index, err));
        let _ = stream.set_nodelay(true);
        let _ = stream.write_all(b"x");
        let _ = stream.shutdown(Shutdown::Both);
        if index % 64 == 0 {
            thread::sleep(Duration::from_millis(1));
        }
    }

    let expected = stream_limit + 1;
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut accepted = 0usize;
    while accepted < expected && Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let Some(event) = target.recv_event(remaining) else {
            break;
        };
        if matches!(event, TargetEvent::Accepted) {
            accepted = accepted.saturating_add(1);
        }
    }

    if accepted < expected {
        let client_snapshot = log_snapshot(&client_logs);
        let server_snapshot = log_snapshot(&server_logs);
        panic!(
            "expected {} target accepts, got {}\nclient logs:\n{}\nserver logs:\n{}",
            expected, accepted, client_snapshot, server_snapshot
        );
    }
}

#[test]
fn stream_limit_server_close_allows_next_stream() {
    let root = workspace_root();
    let client_bin = ensure_client_bin(&root);
    let server_bin = server_bin_path();

    let (cert, key) = test_cert_and_key(&root);

    let dns_port = match pick_udp_port() {
        Ok(port) => port,
        Err(err) => {
            eprintln!("skipping stream limit server close e2e test: {}", err);
            return;
        }
    };
    let tcp_port = match pick_tcp_port() {
        Ok(port) => port,
        Err(err) => {
            eprintln!("skipping stream limit server close e2e test: {}", err);
            return;
        }
    };

    let target = match spawn_accept_loop_target(|stream, tx, _stop_flag, _index| {
        let _ = tx.send(TargetEvent::Accepted);
        let _ = stream.set_nodelay(true);
        let _ = stream.shutdown(Shutdown::Both);
        None
    }) {
        Ok(target) => target,
        Err(err) => {
            eprintln!("skipping stream limit server close e2e test: {}", err);
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
        "skipping stream limit server close e2e test: server failed to start",
        Duration::from_millis(200),
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

    let stream_limit = derive_stream_limit(&client_logs);
    let client_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, tcp_port));
    let mut accepted = 0usize;
    for index in 0..=stream_limit {
        let mut stream = TcpStream::connect_timeout(&client_addr, Duration::from_secs(2))
            .unwrap_or_else(|err| panic!("connect stream {}: {}", index, err));
        let _ = stream.set_nodelay(true);
        let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
        stream
            .write_all(b"x")
            .unwrap_or_else(|err| panic!("write stream {}: {}", index, err));

        match target.recv_event(Duration::from_secs(2)) {
            Some(TargetEvent::Accepted) => {
                accepted = accepted.saturating_add(1);
            }
            None => {
                let client_snapshot = log_snapshot(&client_logs);
                let server_snapshot = log_snapshot(&server_logs);
                panic!(
                    "stream {}: target did not accept\nclient logs:\n{}\nserver logs:\n{}",
                    index, client_snapshot, server_snapshot
                );
            }
        }

        let deadline = Instant::now() + STREAM_CLOSE_TIMEOUT;
        let mut buf = [0u8; 1];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(_) => continue,
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    if Instant::now() >= deadline {
                        let client_snapshot = log_snapshot(&client_logs);
                        let server_snapshot = log_snapshot(&server_logs);
                        panic!(
                            "stream {}: timed out waiting for server close\nclient logs:\n{}\nserver logs:\n{}",
                            index, client_snapshot, server_snapshot
                        );
                    }
                    continue;
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::BrokenPipe
                            | std::io::ErrorKind::NotConnected
                            | std::io::ErrorKind::UnexpectedEof
                    ) =>
                {
                    break;
                }
                Err(err) => {
                    let client_snapshot = log_snapshot(&client_logs);
                    let server_snapshot = log_snapshot(&server_logs);
                    panic!(
                        "stream {}: read error {:?}\nclient logs:\n{}\nserver logs:\n{}",
                        index, err, client_snapshot, server_snapshot
                    );
                }
            }
        }

        if index % 64 == 0 {
            thread::sleep(Duration::from_millis(1));
        }
    }

    let expected = stream_limit + 1;
    if accepted < expected {
        let client_snapshot = log_snapshot(&client_logs);
        let server_snapshot = log_snapshot(&server_logs);
        panic!(
            "expected {} target accepts, got {}\nclient logs:\n{}\nserver logs:\n{}",
            expected, accepted, client_snapshot, server_snapshot
        );
    }
}
