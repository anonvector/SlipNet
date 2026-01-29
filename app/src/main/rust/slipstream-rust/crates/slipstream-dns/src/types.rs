use std::fmt;

pub const RR_A: u16 = 1;
pub const RR_TXT: u16 = 16;
pub const RR_OPT: u16 = 41;
pub const CLASS_IN: u16 = 1;
pub const EDNS_UDP_PAYLOAD: u16 = 1232;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rcode {
    Ok,
    FormatError,
    ServerFailure,
    NameError,
}

impl Rcode {
    pub fn to_u8(self) -> u8 {
        match self {
            Rcode::Ok => 0,
            Rcode::FormatError => 1,
            Rcode::ServerFailure => 2,
            Rcode::NameError => 3,
        }
    }

    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Rcode::Ok),
            1 => Some(Rcode::FormatError),
            2 => Some(Rcode::ServerFailure),
            3 => Some(Rcode::NameError),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone)]
pub struct DecodedQuery {
    pub id: u16,
    pub rd: bool,
    pub cd: bool,
    pub question: Question,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum DecodeQueryError {
    Drop,
    Reply {
        id: u16,
        rd: bool,
        cd: bool,
        question: Option<Question>,
        rcode: Rcode,
    },
}

#[derive(Debug, Clone)]
pub struct QueryParams<'a> {
    pub id: u16,
    pub qname: &'a str,
    pub qtype: u16,
    pub qclass: u16,
    pub rd: bool,
    pub cd: bool,
    pub qdcount: u16,
    pub is_query: bool,
}

#[derive(Debug, Clone)]
pub struct ResponseParams<'a> {
    pub id: u16,
    pub rd: bool,
    pub cd: bool,
    pub question: &'a Question,
    pub payload: Option<&'a [u8]>,
    pub rcode: Option<Rcode>,
}

#[derive(Debug, Clone)]
pub struct DnsError {
    message: String,
}

impl DnsError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for DnsError {}
