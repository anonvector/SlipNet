mod support;

use std::path::PathBuf;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use support::{
    ensure_client_bin, log_snapshot, pick_tcp_port, pick_udp_port, poke_client_with_payload,
    server_bin_path, spawn_client, spawn_server, terminate_process, test_cert_and_key,
    wait_for_log, wait_for_log_since, workspace_root, ClientArgs, ServerArgs,
};

#[test]
fn restart_reconnects_idle_client() {
    let root = workspace_root();
    let client_bin = ensure_client_bin(&root);
    let server_bin = server_bin_path();

    let (cert, key) = test_cert_and_key(&root);

    let dns_port = match pick_udp_port() {
        Ok(port) => port,
        Err(err) => {
            eprintln!("skipping restart reconnect e2e test: {}", err);
            return;
        }
    };
    let tcp_port = match pick_tcp_port() {
        Ok(port) => port,
        Err(err) => {
            eprintln!("skipping restart reconnect e2e test: {}", err);
            return;
        }
    };
    let domain = "test.example.com";
    let reset_seed_path = temp_path("reset-seed");

    let (mut server, _server_logs) = spawn_server(ServerArgs {
        server_bin: &server_bin,
        dns_listen_host: Some("127.0.0.1"),
        dns_port,
        target_address: "127.0.0.1:1",
        domains: &[domain],
        cert: &cert,
        key: &key,
        reset_seed_path: Some(&reset_seed_path),
        fallback_addr: None,
        idle_timeout_seconds: None,
        envs: &[],
        rust_log: "info",
        capture_logs: false,
    });
    thread::sleep(Duration::from_millis(200));
    if server.has_exited() {
        eprintln!("skipping restart reconnect e2e test: server failed to start");
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

    terminate_process(&mut server, Duration::from_secs(2));
    let (mut server, _server_logs) = spawn_server(ServerArgs {
        server_bin: &server_bin,
        dns_listen_host: Some("127.0.0.1"),
        dns_port,
        target_address: "127.0.0.1:1",
        domains: &[domain],
        cert: &cert,
        key: &key,
        reset_seed_path: Some(&reset_seed_path),
        fallback_addr: None,
        idle_timeout_seconds: None,
        envs: &[],
        rust_log: "info",
        capture_logs: false,
    });
    thread::sleep(Duration::from_millis(200));
    if server.has_exited() {
        let snapshot = log_snapshot(&client_logs);
        panic!("server failed to restart\n{}", snapshot);
    }

    let payload = [0u8; 128];
    let already_reset = log_snapshot(&client_logs).contains("stateless_reset");
    let reset_delay = if already_reset {
        Duration::ZERO
    } else {
        let send_start = std::time::Instant::now();
        if !poke_client_with_payload(tcp_port, Duration::from_secs(2), &payload) {
            let snapshot = log_snapshot(&client_logs);
            panic!(
                "client did not accept TCP payload after restart\n{}",
                snapshot
            );
        }
        let reset_delay = wait_for_log_since(
            &client_logs,
            "stateless_reset",
            send_start,
            Duration::from_secs(5),
        );
        let Some(reset_delay) = reset_delay else {
            let snapshot = log_snapshot(&client_logs);
            panic!(
                "client did not observe stateless reset after restart\n{}",
                snapshot
            );
        };
        reset_delay
    };
    if reset_delay > Duration::from_secs(1) {
        let snapshot = log_snapshot(&client_logs);
        panic!(
            "stateless reset took too long after restart ({} ms)\n{}",
            reset_delay.as_millis(),
            snapshot
        );
    }
    if !wait_for_log(&client_logs, "Connection ready", Duration::from_secs(15)) {
        let snapshot = log_snapshot(&client_logs);
        panic!("client did not reconnect after restart\n{}", snapshot);
    }

    let _ = std::fs::remove_file(&reset_seed_path);
}

fn temp_path(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    path.push(format!(
        "slipstream-test-{}-{}-{}",
        name,
        std::process::id(),
        suffix
    ));
    path
}
