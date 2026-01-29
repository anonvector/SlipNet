use std::fmt;

const ENCODE_TABLE: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base32Error {
    InvalidLength,
    InvalidChar,
    InvalidPadding,
}

impl fmt::Display for Base32Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Base32Error::InvalidLength => "invalid base32 length",
            Base32Error::InvalidChar => "invalid base32 character",
            Base32Error::InvalidPadding => "invalid base32 padding",
        };
        write!(f, "{}", message)
    }
}

impl std::error::Error for Base32Error {}

pub fn encode(input: &[u8]) -> String {
    if input.is_empty() {
        return String::new();
    }

    let mut out = String::with_capacity((input.len() * 8).div_ceil(5));
    let mut buffer: u32 = 0;
    let mut bits: u8 = 0;

    for &byte in input {
        buffer = (buffer << 8) | byte as u32;
        bits += 8;

        while bits >= 5 {
            let shift = bits - 5;
            let index = ((buffer >> shift) & 0x1f) as usize;
            out.push(ENCODE_TABLE[index] as char);
            bits -= 5;
        }
    }

    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(ENCODE_TABLE[index] as char);
    }

    out
}

pub fn decode(input: &str) -> Result<Vec<u8>, Base32Error> {
    if input.is_empty() {
        return Ok(Vec::new());
    }

    let mut cleaned = Vec::with_capacity(input.len());
    let mut saw_pad = false;
    for b in input.bytes() {
        if b == b'.' {
            continue;
        }
        if b == b'=' {
            saw_pad = true;
            cleaned.push(b);
            continue;
        }
        if saw_pad {
            return Err(Base32Error::InvalidPadding);
        }
        cleaned.push(b);
    }

    if cleaned.is_empty() {
        return Ok(Vec::new());
    }

    let mut len = cleaned.len();
    let mut pad = 0usize;
    while len > 0 && cleaned[len - 1] == b'=' {
        pad += 1;
        len -= 1;
    }

    if pad > 0 {
        if cleaned[..len].contains(&b'=') {
            return Err(Base32Error::InvalidPadding);
        }
        if cleaned.len() < 8 || cleaned.len() % 8 != 0 || pad > 6 {
            return Err(Base32Error::InvalidPadding);
        }
    }

    let data = &cleaned[..len];
    let rem = data.len() % 8;
    if rem != 0 && rem != 2 && rem != 4 && rem != 5 && rem != 7 {
        return Err(Base32Error::InvalidLength);
    }

    let mut out = Vec::with_capacity(data.len() * 5 / 8 + 4);
    let mut index = 0usize;

    while index + 8 <= data.len() {
        let v1 = decode_value(data[index])?;
        let v2 = decode_value(data[index + 1])?;
        let v3 = decode_value(data[index + 2])?;
        let v4 = decode_value(data[index + 3])?;
        let v5 = decode_value(data[index + 4])?;
        let v6 = decode_value(data[index + 5])?;
        let v7 = decode_value(data[index + 6])?;
        let v8 = decode_value(data[index + 7])?;

        out.push((v1 << 3) | (v2 >> 2));
        out.push((v2 << 6) | (v3 << 1) | (v4 >> 4));
        out.push((v4 << 4) | (v5 >> 1));
        out.push((v5 << 7) | (v6 << 2) | (v7 >> 3));
        out.push((v7 << 5) | v8);

        index += 8;
    }

    let remaining = data.len() - index;
    if remaining > 0 {
        let v1 = decode_value(data[index])?;
        let v2 = decode_value(data[index + 1])?;
        out.push((v1 << 3) | (v2 >> 2));

        if remaining == 2 {
            return Ok(out);
        }

        let v3 = decode_value(data[index + 2])?;
        let v4 = decode_value(data[index + 3])?;
        out.push((v2 << 6) | (v3 << 1) | (v4 >> 4));

        if remaining == 4 {
            return Ok(out);
        }

        let v5 = decode_value(data[index + 4])?;
        out.push((v4 << 4) | (v5 >> 1));

        if remaining == 5 {
            return Ok(out);
        }

        let v6 = decode_value(data[index + 5])?;
        let v7 = decode_value(data[index + 6])?;
        out.push((v5 << 7) | (v6 << 2) | (v7 >> 3));
    }

    Ok(out)
}

fn decode_value(b: u8) -> Result<u8, Base32Error> {
    match b {
        b'A'..=b'Z' => Ok(b - b'A'),
        b'a'..=b'z' => Ok(b - b'a'),
        b'2'..=b'7' => Ok(b - b'2' + 26),
        _ => Err(Base32Error::InvalidChar),
    }
}
