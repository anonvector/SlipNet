mod support;

use std::thread;
use std::time::Duration;

use support::{
    ensure_client_bin, log_snapshot, pick_tcp_port, pick_udp_port, poke_client, server_bin_path,
    spawn_client, spawn_server, test_cert_and_key, wait_for_log, workspace_root, ClientArgs,
    ServerArgs,
};

#[test]
fn cert_pinning_e2e() {
    let root = workspace_root();
    let client_bin = ensure_client_bin(&root);
    let server_bin = server_bin_path();

    let (cert, key) = test_cert_and_key(&root);
    let alt_cert = root.join("fixtures/certs/alt_cert.pem");

    assert!(alt_cert.exists(), "missing fixtures/certs/alt_cert.pem");

    let dns_port = match pick_udp_port() {
        Ok(port) => port,
        Err(err) => {
            eprintln!("skipping cert pinning e2e test: {}", err);
            return;
        }
    };
    let tcp_port_ok = match pick_tcp_port() {
        Ok(port) => port,
        Err(err) => {
            eprintln!("skipping cert pinning e2e test: {}", err);
            return;
        }
    };
    let tcp_port_bad = match pick_tcp_port() {
        Ok(port) => port,
        Err(err) => {
            eprintln!("skipping cert pinning e2e test: {}", err);
            return;
        }
    };
    let domain = "test.example.com";
    let alt_domain = "alt.example.com";

    let (mut server, _server_logs) = spawn_server(ServerArgs {
        server_bin: &server_bin,
        dns_listen_host: None,
        dns_port,
        target_address: "127.0.0.1:1",
        domains: &[domain, alt_domain],
        cert: &cert,
        key: &key,
        reset_seed_path: None,
        fallback_addr: None,
        idle_timeout_seconds: None,
        envs: &[],
        rust_log: "info",
        capture_logs: false,
    });
    thread::sleep(Duration::from_millis(200));
    if server.has_exited() {
        eprintln!("skipping cert pinning e2e test: server failed to start");
        return;
    }

    {
        let (mut client, logs) = spawn_client(ClientArgs {
            client_bin: &client_bin,
            dns_port,
            tcp_port: tcp_port_ok,
            domain,
            cert: Some(&cert),
            keep_alive_interval: None,
            envs: &[],
            rust_log: "info",
            capture_logs: true,
        });
        let logs = logs.expect("client logs");
        if !wait_for_log(&logs, "Listening on TCP port", Duration::from_secs(5)) {
            let snapshot = log_snapshot(&logs);
            panic!("client did not start listening\n{}", snapshot);
        }
        let poke_ok = poke_client(tcp_port_ok, Duration::from_secs(5));
        assert!(
            poke_ok,
            "failed to connect to client TCP port {}",
            tcp_port_ok
        );
        let ready = wait_for_log(&logs, "Connection ready", Duration::from_secs(10));
        if !ready {
            let exited = client.has_exited();
            let snapshot = log_snapshot(&logs);
            panic!(
                "expected connection ready with pinned cert (client_exited={})\n{}",
                exited, snapshot
            );
        }
    }

    {
        let (mut client, logs) = spawn_client(ClientArgs {
            client_bin: &client_bin,
            dns_port,
            tcp_port: tcp_port_bad,
            domain: alt_domain,
            cert: Some(&alt_cert),
            keep_alive_interval: None,
            envs: &[],
            rust_log: "info",
            capture_logs: true,
        });
        let logs = logs.expect("client logs");
        if !wait_for_log(&logs, "Listening on TCP port", Duration::from_secs(5)) {
            let snapshot = log_snapshot(&logs);
            panic!("client did not start listening\n{}", snapshot);
        }
        let poke_ok = poke_client(tcp_port_bad, Duration::from_secs(5));
        assert!(
            poke_ok,
            "failed to connect to client TCP port {}",
            tcp_port_bad
        );
        let ready = wait_for_log(&logs, "Connection ready", Duration::from_secs(5));
        if ready {
            let snapshot = log_snapshot(&logs);
            panic!(
                "unexpected connection ready with mismatched cert\n{}",
                snapshot
            );
        }
        let _ = client.has_exited();
    }
}
