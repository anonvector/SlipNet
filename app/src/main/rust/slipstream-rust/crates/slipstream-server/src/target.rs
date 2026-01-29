use crate::server::{
    Command, StreamKey, StreamWrite, DEFAULT_TCP_RCVBUF_BYTES, STREAM_READ_CHUNK_BYTES,
    TARGET_WRITE_COALESCE_DEFAULT_BYTES,
};
use slipstream_core::tcp::{stream_read_limit_chunks, tcp_send_buffer_bytes};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream as TokioTcpStream;
use tokio::sync::{mpsc, watch};
use tracing::{debug, warn};

pub(crate) fn spawn_target_connector(
    key: StreamKey,
    target_addr: SocketAddr,
    command_tx: mpsc::UnboundedSender<Command>,
    debug_streams: bool,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        if *shutdown_rx.borrow() {
            return;
        }
        let connect = TokioTcpStream::connect(target_addr);
        let stream = tokio::select! {
            _ = shutdown_rx.changed() => {
                return;
            }
            result = connect => result,
        };
        if *shutdown_rx.borrow() {
            return;
        }
        match stream {
            Ok(stream) => {
                let _ = stream.set_nodelay(true);
                let read_limit = stream_read_limit_chunks(
                    &stream,
                    DEFAULT_TCP_RCVBUF_BYTES,
                    STREAM_READ_CHUNK_BYTES,
                );
                let (data_tx, data_rx) = mpsc::channel(read_limit);
                let send_buffer_bytes = tcp_send_buffer_bytes(&stream)
                    .filter(|bytes| *bytes > 0)
                    .unwrap_or(TARGET_WRITE_COALESCE_DEFAULT_BYTES);
                let (read_half, write_half) = stream.into_split();
                let (write_tx, write_rx) = mpsc::unbounded_channel();
                let send_pending = Arc::new(AtomicBool::new(false));
                spawn_target_reader(
                    key,
                    read_half,
                    data_tx,
                    command_tx.clone(),
                    send_pending.clone(),
                    debug_streams,
                    shutdown_rx.clone(),
                );
                spawn_target_writer(
                    key,
                    write_half,
                    write_rx,
                    command_tx.clone(),
                    shutdown_rx,
                    send_buffer_bytes,
                );
                let _ = command_tx.send(Command::StreamConnected {
                    cnx_id: key.cnx,
                    stream_id: key.stream_id,
                    write_tx,
                    data_rx,
                    send_pending,
                });
            }
            Err(err) => {
                warn!(
                    "stream {:?}: target connect failed err={} kind={:?}",
                    key.stream_id,
                    err,
                    err.kind()
                );
                let _ = command_tx.send(Command::StreamConnectError {
                    cnx_id: key.cnx,
                    stream_id: key.stream_id,
                });
            }
        }
    });
}

pub(crate) fn spawn_target_reader(
    key: StreamKey,
    mut read_half: tokio::net::tcp::OwnedReadHalf,
    data_tx: mpsc::Sender<Vec<u8>>,
    command_tx: mpsc::UnboundedSender<Command>,
    send_pending: Arc<AtomicBool>,
    debug_streams: bool,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; STREAM_READ_CHUNK_BYTES];
        let mut total = 0u64;
        loop {
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                }
                read = read_half.read(&mut buf) => {
                    match read {
                        Ok(0) => {
                            if debug_streams {
                                debug!(
                                    "stream {:?}: target eof read_bytes={}",
                                    key.stream_id, total
                                );
                            }
                            let _ = command_tx.send(Command::StreamClosed {
                                cnx_id: key.cnx,
                                stream_id: key.stream_id,
                            });
                            break;
                        }
                        Ok(n) => {
                            total = total.saturating_add(n as u64);
                            let data = buf[..n].to_vec();
                            if data_tx.send(data).await.is_err() {
                                break;
                            }
                            if !send_pending.swap(true, Ordering::SeqCst) {
                                let _ = command_tx.send(Command::StreamReadable {
                                    cnx_id: key.cnx,
                                    stream_id: key.stream_id,
                                });
                            }
                        }
                        Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {
                            continue;
                        }
                        Err(err) => {
                            if debug_streams {
                                debug!(
                                    "stream {:?}: target read error after {} bytes (kind={:?} err={})",
                                    key.stream_id,
                                    total,
                                    err.kind(),
                                    err
                                );
                            }
                            let _ = command_tx.send(Command::StreamReadError {
                                cnx_id: key.cnx,
                                stream_id: key.stream_id,
                            });
                            break;
                        }
                    }
                }
            }
        }
        drop(data_tx);
    });
}

pub(crate) fn spawn_target_writer(
    key: StreamKey,
    mut write_half: tokio::net::tcp::OwnedWriteHalf,
    mut write_rx: mpsc::UnboundedReceiver<StreamWrite>,
    command_tx: mpsc::UnboundedSender<Command>,
    mut shutdown_rx: watch::Receiver<bool>,
    coalesce_max_bytes: usize,
) {
    tokio::spawn(async move {
        let coalesce_max_bytes = coalesce_max_bytes.max(1);
        loop {
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                }
                msg = write_rx.recv() => {
                    let Some(msg) = msg else {
                        break;
                    };
                    match msg {
                        StreamWrite::Data(data) => {
                            let mut buffer = data;
                            let mut saw_fin = false;
                            while buffer.len() < coalesce_max_bytes {
                                match write_rx.try_recv() {
                                    Ok(StreamWrite::Data(more)) => {
                                        buffer.extend_from_slice(&more);
                                        if buffer.len() >= coalesce_max_bytes {
                                            break;
                                        }
                                    }
                                    Ok(StreamWrite::Fin) => {
                                        saw_fin = true;
                                        break;
                                    }
                                    Err(mpsc::error::TryRecvError::Empty) => break,
                                    Err(mpsc::error::TryRecvError::Disconnected) => {
                                        saw_fin = true;
                                        break;
                                    }
                                }
                            }
                            let len = buffer.len();
                            if write_half.write_all(&buffer).await.is_err() {
                                let _ = command_tx.send(Command::StreamWriteError {
                                    cnx_id: key.cnx,
                                    stream_id: key.stream_id,
                                });
                                return;
                            }
                            let _ = command_tx.send(Command::StreamWriteDrained {
                                cnx_id: key.cnx,
                                stream_id: key.stream_id,
                                bytes: len,
                            });
                            if saw_fin {
                                let _ = write_half.shutdown().await;
                                return;
                            }
                        }
                        StreamWrite::Fin => {
                            let _ = write_half.shutdown().await;
                            return;
                        }
                    }
                }
            }
        }
        let _ = write_half.shutdown().await;
    });
}
