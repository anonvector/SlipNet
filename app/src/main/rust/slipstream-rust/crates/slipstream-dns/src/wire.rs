use crate::name::parse_name;
use crate::types::{DecodeQueryError, DnsError, Question, Rcode};

#[derive(Debug, Clone, Copy)]
pub(crate) struct Header {
    pub(crate) id: u16,
    pub(crate) is_response: bool,
    pub(crate) rd: bool,
    pub(crate) cd: bool,
    pub(crate) qdcount: u16,
    pub(crate) ancount: u16,
    pub(crate) rcode: Option<Rcode>,
    pub(crate) offset: usize,
}

pub(crate) fn parse_header(packet: &[u8]) -> Option<Header> {
    if packet.len() < 12 {
        return None;
    }
    let id = read_u16(packet, 0)?;
    let flags = read_u16(packet, 2)?;
    let qdcount = read_u16(packet, 4)?;
    let ancount = read_u16(packet, 6)?;
    let _nscount = read_u16(packet, 8)?;
    let _arcount = read_u16(packet, 10)?;

    let is_response = flags & 0x8000 != 0;
    let rd = flags & 0x0100 != 0;
    let cd = flags & 0x0010 != 0;
    let rcode = Rcode::from_u8((flags & 0x000f) as u8);

    Some(Header {
        id,
        is_response,
        rd,
        cd,
        qdcount,
        ancount,
        rcode,
        offset: 12,
    })
}

#[derive(Debug)]
enum ParseError {
    NoQuestion,
    Malformed,
}

fn parse_first_question(
    packet: &[u8],
    qdcount: u16,
    offset: usize,
) -> Result<Option<Question>, ParseError> {
    if qdcount == 0 {
        return Err(ParseError::NoQuestion);
    }
    let (question, _) = parse_question(packet, offset).map_err(|_| ParseError::Malformed)?;
    Ok(Some(question))
}

pub(crate) fn parse_question_for_reply(
    packet: &[u8],
    qdcount: u16,
    offset: usize,
) -> Result<Option<Question>, DecodeQueryError> {
    match parse_first_question(packet, qdcount, offset) {
        Ok(question) => Ok(question),
        Err(ParseError::NoQuestion) => Ok(None),
        Err(ParseError::Malformed) => Err(DecodeQueryError::Drop),
    }
}

pub(crate) fn parse_question(packet: &[u8], offset: usize) -> Result<(Question, usize), DnsError> {
    let (name, mut offset) = parse_name(packet, offset).map_err(|_| DnsError::new("bad name"))?;
    if offset + 4 > packet.len() {
        return Err(DnsError::new("truncated question"));
    }
    let qtype = read_u16(packet, offset).ok_or_else(|| DnsError::new("truncated qtype"))?;
    offset += 2;
    let qclass = read_u16(packet, offset).ok_or_else(|| DnsError::new("truncated qclass"))?;
    offset += 2;
    Ok((
        Question {
            name,
            qtype,
            qclass,
        },
        offset,
    ))
}

pub(crate) fn read_u16(packet: &[u8], offset: usize) -> Option<u16> {
    if offset + 2 > packet.len() {
        return None;
    }
    Some(u16::from_be_bytes([packet[offset], packet[offset + 1]]))
}

pub(crate) fn read_u32(packet: &[u8], offset: usize) -> Option<u32> {
    if offset + 4 > packet.len() {
        return None;
    }
    Some(u32::from_be_bytes([
        packet[offset],
        packet[offset + 1],
        packet[offset + 2],
        packet[offset + 3],
    ]))
}

pub(crate) fn write_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

pub(crate) fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}
