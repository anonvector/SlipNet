mod support;

use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use slipstream_dns::{encode_query, is_response, QueryParams, CLASS_IN, RR_A};

use support::{
    pick_udp_port, server_bin_path, spawn_server, test_cert_and_key, workspace_root, ServerArgs,
};

struct EchoServer {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
    rx: Receiver<Vec<u8>>,
}

impl EchoServer {
    fn spawn() -> io::Result<Self> {
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        socket.set_read_timeout(Some(Duration::from_millis(100)))?;
        let addr = socket.local_addr()?;
        let (tx, rx) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            let mut buf = [0u8; 2048];
            while !stop_flag.load(Ordering::Relaxed) {
                match socket.recv_from(&mut buf) {
                    Ok((size, peer)) => {
                        let payload = buf[..size].to_vec();
                        let _ = tx.send(payload.clone());
                        let _ = socket.send_to(&payload, peer);
                    }
                    Err(err)
                        if err.kind() == io::ErrorKind::WouldBlock
                            || err.kind() == io::ErrorKind::TimedOut =>
                    {
                        continue;
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            addr,
            stop,
            handle: Some(handle),
            rx,
        })
    }

    fn recv_timeout(&self, timeout: Duration) -> Result<Vec<u8>, mpsc::RecvTimeoutError> {
        self.rx.recv_timeout(timeout)
    }

    fn drain(&self) {
        while self.rx.try_recv().is_ok() {}
    }
}

impl Drop for EchoServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn build_dns_query(qname: &str) -> Vec<u8> {
    encode_query(&QueryParams {
        id: 0x1234,
        qname,
        qtype: RR_A,
        qclass: CLASS_IN,
        rd: true,
        cd: false,
        qdcount: 1,
        is_query: true,
    })
    .expect("encode DNS query")
}

#[test]
fn udp_fallback_e2e() {
    let root = workspace_root();
    let server_bin = server_bin_path();

    let (cert, key) = test_cert_and_key(&root);

    let dns_port = match pick_udp_port() {
        Ok(port) => port,
        Err(err) => {
            eprintln!("skipping udp fallback e2e test: {}", err);
            return;
        }
    };
    let echo = match EchoServer::spawn() {
        Ok(server) => server,
        Err(err) => {
            eprintln!("skipping udp fallback e2e test: {}", err);
            return;
        }
    };
    let domain = "test.example.com";

    let (mut server, _server_logs) = spawn_server(ServerArgs {
        server_bin: &server_bin,
        dns_listen_host: Some("127.0.0.1"),
        dns_port,
        target_address: "127.0.0.1:1",
        domains: &[domain],
        cert: &cert,
        key: &key,
        reset_seed_path: None,
        fallback_addr: Some(echo.addr),
        idle_timeout_seconds: None,
        envs: &[],
        rust_log: "info",
        capture_logs: false,
    });
    thread::sleep(Duration::from_millis(200));
    if server.has_exited() {
        eprintln!("skipping udp fallback e2e test: server failed to start");
        return;
    }

    let server_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, dns_port));
    let mut buf = [0u8; 2048];

    let client_fallback = UdpSocket::bind("127.0.0.1:0").expect("bind fallback client");
    client_fallback
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("set fallback read timeout");
    let non_dns = b"nope";
    client_fallback
        .send_to(non_dns, server_addr)
        .expect("send non-DNS packet");
    let (size, _) = client_fallback
        .recv_from(&mut buf)
        .expect("receive fallback reply");
    assert_eq!(&buf[..size], non_dns, "expected fallback echo");
    let echoed = echo
        .recv_timeout(Duration::from_secs(1))
        .expect("fallback endpoint receive");
    assert_eq!(echoed, non_dns, "fallback endpoint should see non-DNS");
    echo.drain();

    let client_dns = UdpSocket::bind("127.0.0.1:0").expect("bind DNS client");
    client_dns
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("set DNS read timeout");
    let qname = format!("{}.", domain);
    let query = build_dns_query(&qname);
    client_dns
        .send_to(&query, server_addr)
        .expect("send DNS query");
    let (size, _) = client_dns.recv_from(&mut buf).expect("receive DNS reply");
    let response = &buf[..size];
    assert!(is_response(response), "expected DNS response");
    assert_ne!(
        response,
        query.as_slice(),
        "expected DNS response, got echo"
    );
    assert!(
        echo.recv_timeout(Duration::from_millis(200)).is_err(),
        "fallback endpoint should not see DNS query"
    );
}
