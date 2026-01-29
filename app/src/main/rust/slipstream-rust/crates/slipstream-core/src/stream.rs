use std::collections::BTreeMap;

#[derive(Debug)]
pub struct StreamRecvState {
    pub consumed_offset: u64,
    pub sent_offset: u64,
    pub buffered_bytes: usize,
    pub pending_fin: Option<u64>,
    pub fin_enqueued: bool,
    pub chunks: BTreeMap<u64, Vec<u8>>,
}

impl StreamRecvState {
    pub fn new() -> Self {
        Self {
            consumed_offset: 0,
            sent_offset: 0,
            buffered_bytes: 0,
            pending_fin: None,
            fin_enqueued: false,
            chunks: BTreeMap::new(),
        }
    }
}

impl Default for StreamRecvState {
    fn default() -> Self {
        Self::new()
    }
}

pub fn insert_stream_chunk(
    chunks: &mut BTreeMap<u64, Vec<u8>>,
    sent_offset: u64,
    offset: u64,
    data: &[u8],
) -> usize {
    if data.is_empty() {
        return 0;
    }

    let mut start = offset;
    let mut bytes = data;
    if start < sent_offset {
        let delta = (sent_offset - start) as usize;
        if delta >= bytes.len() {
            return 0;
        }
        bytes = &bytes[delta..];
        start = sent_offset;
    }

    let end = start.saturating_add(bytes.len() as u64);
    if end == start {
        return 0;
    }

    let mut cursor = start;
    let mut inserts: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut inserted = 0usize;

    for (seg_start, seg_data) in chunks.range(..end) {
        let seg_start = *seg_start;
        let seg_end = seg_start.saturating_add(seg_data.len() as u64);
        if seg_end <= cursor {
            continue;
        }
        if seg_start > cursor {
            let gap_end = seg_start.min(end);
            let gap_len = (gap_end - cursor) as usize;
            let gap_offset = (cursor - start) as usize;
            inserts.push((cursor, bytes[gap_offset..gap_offset + gap_len].to_vec()));
            inserted = inserted.saturating_add(gap_len);
            cursor = gap_end;
        }
        if seg_end > cursor {
            cursor = seg_end;
        }
        if cursor >= end {
            break;
        }
    }

    if cursor < end {
        let gap_offset = (cursor - start) as usize;
        inserts.push((cursor, bytes[gap_offset..].to_vec()));
        inserted = inserted.saturating_add(bytes.len() - gap_offset);
    }

    for (seg_offset, seg_data) in inserts {
        chunks.insert(seg_offset, seg_data);
    }

    inserted
}
