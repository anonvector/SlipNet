mod support;

use std::thread;
use std::time::Duration;

use support::{
    ensure_client_bin, log_snapshot, pick_tcp_port, pick_udp_port, poke_client_with_payload,
    server_bin_path, spawn_client, spawn_server, test_cert_and_key, wait_for_log, workspace_root,
    ClientArgs, ServerArgs,
};

#[test]
fn idle_gc_closes_connection() {
    let root = workspace_root();
    let client_bin = ensure_client_bin(&root);
    let server_bin = server_bin_path();

    let (cert, key) = test_cert_and_key(&root);

    let dns_port = match pick_udp_port() {
        Ok(port) => port,
        Err(err) => {
            eprintln!("skipping idle gc e2e test: {}", err);
            return;
        }
    };
    let tcp_port = match pick_tcp_port() {
        Ok(port) => port,
        Err(err) => {
            eprintln!("skipping idle gc e2e test: {}", err);
            return;
        }
    };
    let mut recovery_tcp_port = None;
    for _ in 0..10 {
        match pick_tcp_port() {
            Ok(port) if port != tcp_port => {
                recovery_tcp_port = Some(port);
                break;
            }
            Ok(_) => continue,
            Err(err) => {
                eprintln!("skipping idle gc e2e test: {}", err);
                return;
            }
        }
    }
    let Some(recovery_tcp_port) = recovery_tcp_port else {
        eprintln!("skipping idle gc e2e test: could not find distinct TCP port");
        return;
    };
    let domain = "test.example.com";

    let (mut server, server_logs) = spawn_server(ServerArgs {
        server_bin: &server_bin,
        dns_listen_host: Some("127.0.0.1"),
        dns_port,
        target_address: "127.0.0.1:1",
        domains: &[domain],
        cert: &cert,
        key: &key,
        reset_seed_path: None,
        fallback_addr: None,
        idle_timeout_seconds: Some(1),
        envs: &[],
        rust_log: "debug",
        capture_logs: true,
    });
    let server_logs = server_logs.expect("server logs");
    thread::sleep(Duration::from_millis(200));
    if server.has_exited() {
        eprintln!("skipping idle gc e2e test: server failed to start");
        return;
    }

    let (_client, client_logs) = spawn_client(ClientArgs {
        client_bin: &client_bin,
        dns_port,
        tcp_port,
        domain,
        cert: Some(&cert),
        keep_alive_interval: Some(0),
        envs: &[],
        rust_log: "info",
        capture_logs: true,
    });
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

    if !wait_for_log(
        &server_logs,
        "idle gc: closing connection",
        Duration::from_secs(5),
    ) {
        let snapshot = log_snapshot(&server_logs);
        panic!("expected idle gc close log\n{}", snapshot);
    }

    let (_recovery_client, recovery_logs) = spawn_client(ClientArgs {
        client_bin: &client_bin,
        dns_port,
        tcp_port: recovery_tcp_port,
        domain,
        cert: Some(&cert),
        keep_alive_interval: Some(0),
        envs: &[],
        rust_log: "info",
        capture_logs: true,
    });
    let recovery_logs = recovery_logs.expect("recovery client logs");
    if !wait_for_log(
        &recovery_logs,
        "Listening on TCP port",
        Duration::from_secs(5),
    ) {
        let snapshot = log_snapshot(&recovery_logs);
        panic!("recovery client did not start listening\n{}", snapshot);
    }
    if !wait_for_log(&recovery_logs, "Connection ready", Duration::from_secs(10)) {
        let snapshot = log_snapshot(&recovery_logs);
        panic!("recovery client did not become ready\n{}", snapshot);
    }

    let payload = [0u8; 128];
    if !poke_client_with_payload(tcp_port, Duration::from_secs(2), &payload) {
        let snapshot = log_snapshot(&client_logs);
        panic!("client did not accept TCP connection\n{}", snapshot);
    }
    if !wait_for_log(&client_logs, "stateless_reset", Duration::from_secs(5)) {
        let snapshot = log_snapshot(&client_logs);
        panic!("expected stateless reset close\n{}", snapshot);
    }
}
