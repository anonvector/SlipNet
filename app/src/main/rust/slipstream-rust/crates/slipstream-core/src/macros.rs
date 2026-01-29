#[macro_export]
macro_rules! drain_stream_data {
    ($streams:expr, $data_field:ident, $pending:ident, $closed:ident) => {{
        for (key, stream) in $streams.iter_mut() {
            let Some(rx) = stream.$data_field.as_mut() else {
                continue;
            };
            loop {
                match rx.try_recv() {
                    Ok(data) => $pending.push((*key, data)),
                    Err(::tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(::tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        stream.$data_field = None;
                        $closed.push(*key);
                        break;
                    }
                }
            }
        }
    }};
}
