use std::sync::OnceLock;

const DEFAULT_STREAM_QUEUE_MAX_BYTES: usize = 2 * 1024 * 1024;
const DEFAULT_CONN_RESERVE_BYTES: usize = 64 * 1024;

#[derive(Debug, Default)]
pub struct FlowControlState {
    pub queued_bytes: usize,
    pub rx_bytes: u64,
    pub consumed_offset: u64,
    pub fin_offset: Option<u64>,
    pub discarding: bool,
    pub stop_sending_sent: bool,
}

pub trait HasFlowControlState {
    fn flow_control(&self) -> &FlowControlState;
    fn flow_control_mut(&mut self) -> &mut FlowControlState;
}

pub trait FlowControlStream: HasFlowControlState {
    fn queued_bytes(&self) -> usize {
        self.flow_control().queued_bytes
    }

    fn set_queued_bytes(&mut self, value: usize) {
        self.flow_control_mut().queued_bytes = value;
    }

    fn rx_bytes(&self) -> u64 {
        self.flow_control().rx_bytes
    }

    fn set_rx_bytes(&mut self, value: u64) {
        self.flow_control_mut().rx_bytes = value;
    }

    fn consumed_offset(&self) -> u64 {
        self.flow_control().consumed_offset
    }

    fn set_consumed_offset(&mut self, value: u64) {
        self.flow_control_mut().consumed_offset = value;
    }

    fn fin_offset(&self) -> Option<u64> {
        self.flow_control().fin_offset
    }

    fn discarding(&self) -> bool {
        self.flow_control().discarding
    }

    fn set_discarding(&mut self, value: bool) {
        self.flow_control_mut().discarding = value;
    }

    fn stop_sending_sent(&self) -> bool {
        self.flow_control().stop_sending_sent
    }

    fn set_stop_sending_sent(&mut self, value: bool) {
        self.flow_control_mut().stop_sending_sent = value;
    }
}

impl<T: HasFlowControlState> FlowControlStream for T {}

pub struct QueueOverflowOps<Log, Consume, Stop, Err> {
    pub log_overflow: Log,
    pub consume: Consume,
    pub stop_sending: Stop,
    pub on_consume_error: Err,
}

pub struct StreamReceiveConfig {
    pub multi_stream: bool,
    pub reserve_bytes: usize,
    pub max_queue: usize,
}

impl StreamReceiveConfig {
    pub fn new(multi_stream: bool, reserve_bytes: usize) -> Self {
        let max_queue = if multi_stream {
            stream_queue_max_bytes()
        } else {
            0
        };
        Self {
            multi_stream,
            reserve_bytes,
            max_queue,
        }
    }
}

pub struct StreamReceiveOps<Enqueue, Overflow, Consume, Stop, Log, Err> {
    pub enqueue: Enqueue,
    pub on_overflow: Overflow,
    pub consume: Consume,
    pub stop_sending: Stop,
    pub log_overflow: Log,
    pub on_consume_error: Err,
}

pub fn overflow_log_message(
    stream_id: u64,
    queued_bytes: usize,
    incoming_len: usize,
    max_queue: usize,
) -> String {
    format!(
        "stream {}: queued_bytes {} + {} exceeds limit {}; stopping",
        stream_id, queued_bytes, incoming_len, max_queue
    )
}

pub fn consume_error_log_message(
    stream_id: u64,
    context: &str,
    ret: i32,
    current: u64,
    target: u64,
) -> String {
    format!(
        "stream {}: stream_data_consumed failed{} ret={} consumed_offset={} target={}",
        stream_id, context, ret, current, target
    )
}

pub fn promote_error_log_message(stream_id: u64, ret: i32, current: u64, target: u64) -> String {
    consume_error_log_message(stream_id, " during promote", ret, current, target)
}

pub fn stream_queue_max_bytes() -> usize {
    static MAX_BYTES: OnceLock<usize> = OnceLock::new();
    *MAX_BYTES.get_or_init(|| {
        std::env::var("SLIPSTREAM_STREAM_QUEUE_MAX_BYTES")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(DEFAULT_STREAM_QUEUE_MAX_BYTES)
    })
}

pub fn conn_reserve_bytes() -> usize {
    static RESERVE_BYTES: OnceLock<usize> = OnceLock::new();
    *RESERVE_BYTES.get_or_init(|| {
        std::env::var("SLIPSTREAM_CONN_RESERVE_BYTES")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(DEFAULT_CONN_RESERVE_BYTES)
    })
}

pub fn reserve_target_offset(
    rx_bytes: u64,
    queued_bytes: usize,
    fin_offset: Option<u64>,
    reserve_bytes: usize,
) -> u64 {
    let drained = rx_bytes.saturating_sub(queued_bytes as u64);
    let mut target = if reserve_bytes > 0 {
        drained.saturating_add(reserve_bytes as u64).min(rx_bytes)
    } else {
        drained
    };
    if let Some(fin) = fin_offset {
        if target > fin {
            target = fin;
        }
    }
    target
}

pub fn apply_consumed_offset<F, G>(
    consumed_offset: &mut u64,
    target: u64,
    mut consume_fn: F,
    mut on_error: G,
) -> bool
where
    F: FnMut(u64) -> i32,
    G: FnMut(i32, u64, u64),
{
    if target <= *consumed_offset {
        return true;
    }
    let ret = consume_fn(target);
    if ret < 0 {
        on_error(ret, *consumed_offset, target);
        return false;
    }
    *consumed_offset = target;
    true
}

pub fn consume_stream_data<F, G>(
    consumed_offset: &mut u64,
    target: u64,
    consume_fn: F,
    on_error: G,
) -> bool
where
    F: FnMut(u64) -> i32,
    G: FnMut(i32, u64, u64),
{
    apply_consumed_offset(consumed_offset, target, consume_fn, on_error)
}

pub fn handle_queue_overflow<Log, Consume, Stop, Err>(
    queued_bytes: usize,
    incoming_len: usize,
    max_queue: usize,
    rx_bytes: u64,
    consumed_offset: &mut u64,
    stop_sending_sent: &mut bool,
    mut ops: QueueOverflowOps<Log, Consume, Stop, Err>,
) -> bool
where
    Log: FnMut(usize, usize, usize),
    Consume: FnMut(u64) -> i32,
    Stop: FnMut(),
    Err: FnMut(i32, u64, u64),
{
    let projected = queued_bytes.saturating_add(incoming_len);
    if projected <= max_queue {
        return false;
    }
    (ops.log_overflow)(queued_bytes, incoming_len, max_queue);
    let _ = apply_consumed_offset(
        consumed_offset,
        rx_bytes,
        &mut ops.consume,
        &mut ops.on_consume_error,
    );
    if !*stop_sending_sent {
        (ops.stop_sending)();
        *stop_sending_sent = true;
    }
    true
}

pub struct PromoteEntry<'a> {
    pub stream_id: u64,
    pub rx_bytes: u64,
    pub consumed_offset: &'a mut u64,
    pub discarding: bool,
}

pub fn promote_consumed_offset<F, G>(
    rx_bytes: u64,
    consumed_offset: &mut u64,
    mut consume_fn: F,
    mut on_error: G,
) where
    F: FnMut(u64) -> i32,
    G: FnMut(i32, u64),
{
    if *consumed_offset >= rx_bytes {
        return;
    }
    let _ = apply_consumed_offset(
        consumed_offset,
        rx_bytes,
        &mut consume_fn,
        |ret, current, _| {
            on_error(ret, current);
        },
    );
}

pub fn promote_streams<'a, I, Consume, Log>(entries: I, mut consume_fn: Consume, mut on_error: Log)
where
    I: IntoIterator<Item = PromoteEntry<'a>>,
    Consume: FnMut(u64, u64) -> i32,
    Log: FnMut(u64, i32, u64, u64),
{
    for entry in entries {
        if entry.discarding {
            continue;
        }
        let stream_id = entry.stream_id;
        let rx_bytes = entry.rx_bytes;
        promote_consumed_offset(
            rx_bytes,
            entry.consumed_offset,
            |new_offset| consume_fn(stream_id, new_offset),
            |ret, consumed_offset| on_error(stream_id, ret, consumed_offset, rx_bytes),
        );
    }
}

pub fn handle_stream_receive<S, Enqueue, Overflow, Consume, Stop, Log, Err>(
    stream: &mut S,
    incoming_len: usize,
    config: StreamReceiveConfig,
    mut ops: StreamReceiveOps<Enqueue, Overflow, Consume, Stop, Log, Err>,
) -> bool
where
    S: FlowControlStream,
    Enqueue: FnMut(&mut S) -> Result<(), ()>,
    Overflow: FnMut(&mut S),
    Consume: FnMut(u64) -> i32,
    Stop: FnMut(),
    Log: FnMut(usize, usize, usize),
    Err: FnMut(i32, u64, u64),
{
    if incoming_len == 0 {
        return false;
    }

    let mut queued_bytes = stream.queued_bytes();
    let mut rx_bytes = stream.rx_bytes();
    let mut consumed_offset = stream.consumed_offset();
    let fin_offset = stream.fin_offset();
    let mut discarding = stream.discarding();
    let mut stop_sending_sent = stream.stop_sending_sent();
    let mut reset_stream = false;

    rx_bytes = rx_bytes.saturating_add(incoming_len as u64);
    stream.set_rx_bytes(rx_bytes);

    if discarding {
        let _ = consume_stream_data(
            &mut consumed_offset,
            rx_bytes,
            &mut ops.consume,
            &mut ops.on_consume_error,
        );
    } else if config.multi_stream {
        let overflowed = handle_queue_overflow(
            queued_bytes,
            incoming_len,
            config.max_queue,
            rx_bytes,
            &mut consumed_offset,
            &mut stop_sending_sent,
            QueueOverflowOps {
                log_overflow: &mut ops.log_overflow,
                consume: &mut ops.consume,
                stop_sending: &mut ops.stop_sending,
                on_consume_error: &mut ops.on_consume_error,
            },
        );
        if overflowed {
            discarding = true;
            queued_bytes = 0;
            stream.set_discarding(true);
            stream.set_queued_bytes(0);
            (ops.on_overflow)(stream);
        } else if (ops.enqueue)(stream).is_err() {
            reset_stream = true;
        } else {
            queued_bytes = queued_bytes.saturating_add(incoming_len);
        }

        if !discarding
            && !consume_stream_data(
                &mut consumed_offset,
                rx_bytes,
                &mut ops.consume,
                &mut ops.on_consume_error,
            )
        {
            reset_stream = true;
        }
    } else {
        if (ops.enqueue)(stream).is_err() {
            reset_stream = true;
        } else {
            queued_bytes = queued_bytes.saturating_add(incoming_len);
        }

        if config.reserve_bytes > 0
            && !discarding
            && !consume_stream_data(
                &mut consumed_offset,
                reserve_target_offset(rx_bytes, queued_bytes, fin_offset, config.reserve_bytes),
                &mut ops.consume,
                &mut ops.on_consume_error,
            )
        {
            reset_stream = true;
        }
    }

    stream.set_queued_bytes(queued_bytes);
    stream.set_consumed_offset(consumed_offset);
    stream.set_discarding(discarding);
    stream.set_stop_sending_sent(stop_sending_sent);

    reset_stream
}
