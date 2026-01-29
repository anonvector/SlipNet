use std::fs;
use std::path::Path;

use serde::Deserialize;
use slipstream_dns::{
    decode_query, decode_response, encode_query, encode_response, DecodeQueryError, QueryParams,
    Question, Rcode, ResponseParams, CLASS_IN, RR_A, RR_TXT,
};

#[derive(Debug, Deserialize)]
struct VectorFile {
    schema_version: u32,
    vectors: Vec<Vector>,
}

#[derive(Debug, Deserialize)]
struct Vector {
    name: String,
    domain: String,
    id: u16,
    payload_len: usize,
    payload_hex: String,
    mode: String,
    expected_action: String,
    qname: String,
    query: Packet,
    response_ok: Option<ResponsePacket>,
    response_no_data: Option<ResponsePacket>,
    response_error: Option<ResponsePacket>,
}

#[derive(Debug, Deserialize)]
struct Packet {
    packet_len: usize,
    packet_hex: String,
}

#[derive(Debug, Deserialize)]
struct ResponsePacket {
    rcode: String,
    packet_len: usize,
    packet_hex: String,
}

#[test]
fn vectors_match_codec() {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/vectors/dns-vectors.json");
    let data = fs::read_to_string(path).expect("read dns-vectors.json");
    let vectors: VectorFile = serde_json::from_str(&data).expect("parse dns-vectors.json");
    assert_eq!(vectors.schema_version, 2);

    for vector in vectors.vectors {
        let query_bytes = decode_hex(&vector.query.packet_hex);
        assert_eq!(
            query_bytes.len(),
            vector.query.packet_len,
            "{}",
            vector.name
        );

        let is_raw = vector.mode == "raw_query_hex" || vector.expected_action == "drop";
        if is_raw {
            match decode_query(&query_bytes, &vector.domain) {
                Err(DecodeQueryError::Drop) => {}
                other => panic!("{}: expected drop, got {:?}", vector.name, other),
            }
            continue;
        }

        let (qtype, qdcount, is_query) = query_mode(&vector.mode);
        let encoded_query = encode_query(&QueryParams {
            id: vector.id,
            qname: &vector.qname,
            qtype,
            qclass: CLASS_IN,
            rd: true,
            cd: false,
            qdcount,
            is_query,
        })
        .expect("encode query");
        assert_eq!(
            encoded_query, query_bytes,
            "{}: query mismatch",
            vector.name
        );

        match decode_query(&query_bytes, &vector.domain) {
            Ok(decoded) => {
                assert_eq!(decoded.id, vector.id, "{}", vector.name);
                assert_eq!(decoded.question.name, vector.qname, "{}", vector.name);
                assert_eq!(decoded.question.qtype, qtype, "{}", vector.name);
                let payload = decode_hex(&vector.payload_hex);
                assert_eq!(payload.len(), vector.payload_len, "{}", vector.name);
                assert_eq!(decoded.payload, payload, "{}", vector.name);
            }
            Err(DecodeQueryError::Reply { rcode, .. }) => {
                let expected = vector
                    .response_error
                    .as_ref()
                    .map(|resp| rcode_from_str(&resp.rcode))
                    .unwrap_or(Rcode::NameError);
                assert_eq!(rcode, expected, "{}", vector.name);
            }
            Err(DecodeQueryError::Drop) => {
                panic!("{}: unexpected drop", vector.name);
            }
        }

        let question = Question {
            name: vector.qname.clone(),
            qtype,
            qclass: CLASS_IN,
        };

        if let Some(resp) = &vector.response_ok {
            let payload = decode_hex(&vector.payload_hex);
            let encoded = encode_response(&ResponseParams {
                id: vector.id,
                rd: true,
                cd: false,
                question: &question,
                payload: Some(&payload),
                rcode: None,
            })
            .expect("encode response_ok");
            let expected = decode_hex(&resp.packet_hex);
            assert_eq!(encoded.len(), resp.packet_len, "{}", vector.name);
            assert_eq!(encoded, expected, "{}: response_ok mismatch", vector.name);
            let decoded = decode_response(&expected).expect("decode response_ok");
            assert_eq!(decoded, payload, "{}: response_ok payload", vector.name);
        }

        if let Some(resp) = &vector.response_no_data {
            let encoded = encode_response(&ResponseParams {
                id: vector.id,
                rd: true,
                cd: false,
                question: &question,
                payload: None,
                rcode: None,
            })
            .expect("encode response_no_data");
            let expected = decode_hex(&resp.packet_hex);
            assert_eq!(encoded.len(), resp.packet_len, "{}", vector.name);
            assert_eq!(
                encoded, expected,
                "{}: response_no_data mismatch",
                vector.name
            );
            assert!(
                decode_response(&expected).is_none(),
                "{}: response_no_data should be ignored",
                vector.name
            );
        }

        if let Some(resp) = &vector.response_error {
            let rcode = rcode_from_str(&resp.rcode);
            let encoded = encode_response(&ResponseParams {
                id: vector.id,
                rd: true,
                cd: false,
                question: &question,
                payload: None,
                rcode: Some(rcode),
            })
            .expect("encode response_error");
            let expected = decode_hex(&resp.packet_hex);
            assert_eq!(encoded.len(), resp.packet_len, "{}", vector.name);
            assert_eq!(
                encoded, expected,
                "{}: response_error mismatch",
                vector.name
            );
            assert!(
                decode_response(&expected).is_none(),
                "{}: response_error should be ignored",
                vector.name
            );
        }
    }
}

fn query_mode(mode: &str) -> (u16, u16, bool) {
    match mode {
        "non_txt" => (RR_A, 1, true),
        "qdcount_zero" => (RR_TXT, 0, true),
        "not_query" => (RR_TXT, 1, false),
        _ => (RR_TXT, 1, true),
    }
}

fn rcode_from_str(rcode: &str) -> Rcode {
    match rcode {
        "OK" => Rcode::Ok,
        "FORMAT_ERROR" => Rcode::FormatError,
        "SERVER_FAILURE" => Rcode::ServerFailure,
        "NAME_ERROR" => Rcode::NameError,
        other => panic!("unknown rcode: {}", other),
    }
}

fn decode_hex(hex: &str) -> Vec<u8> {
    if hex.is_empty() {
        return Vec::new();
    }
    assert!(hex.len().is_multiple_of(2), "hex length must be even");
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let value = u8::from_str_radix(std::str::from_utf8(&bytes[i..i + 2]).unwrap(), 16)
            .expect("valid hex");
        out.push(value);
    }
    out
}
