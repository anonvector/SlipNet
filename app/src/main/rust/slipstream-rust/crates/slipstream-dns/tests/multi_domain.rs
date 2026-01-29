use slipstream_dns::{
    build_qname, decode_query_with_domains, encode_query, DecodeQueryError, QueryParams, Rcode,
    CLASS_IN, RR_TXT,
};

#[test]
fn decode_query_with_domains_accepts_any_match() {
    let payload = vec![1u8, 2, 3];
    let qname = build_qname(&payload, "example.com").expect("build qname");
    let query = encode_query(&QueryParams {
        id: 42,
        qname: &qname,
        qtype: RR_TXT,
        qclass: CLASS_IN,
        rd: true,
        cd: false,
        qdcount: 1,
        is_query: true,
    })
    .expect("encode query");

    let decoded = decode_query_with_domains(&query, &["alt.example.com", "example.com"])
        .expect("decode query");
    assert_eq!(decoded.payload, payload);
}

#[test]
fn decode_query_with_domains_prefers_longest_suffix() {
    let payload = vec![9u8, 8, 7, 6, 5];
    let qname = build_qname(&payload, "tunnel.example.com").expect("build qname");
    let query = encode_query(&QueryParams {
        id: 7,
        qname: &qname,
        qtype: RR_TXT,
        qclass: CLASS_IN,
        rd: true,
        cd: false,
        qdcount: 1,
        is_query: true,
    })
    .expect("encode query");

    let decoded = decode_query_with_domains(&query, &["example.com", "tunnel.example.com"])
        .expect("decode query");
    assert_eq!(decoded.payload, payload);
}

#[test]
fn decode_query_with_domains_rejects_unknown_domain() {
    let payload = vec![1u8, 2, 3];
    let qname = build_qname(&payload, "example.com").expect("build qname");
    let query = encode_query(&QueryParams {
        id: 99,
        qname: &qname,
        qtype: RR_TXT,
        qclass: CLASS_IN,
        rd: true,
        cd: false,
        qdcount: 1,
        is_query: true,
    })
    .expect("encode query");

    match decode_query_with_domains(&query, &["other.com"]) {
        Err(DecodeQueryError::Reply { .. }) => {}
        other => panic!("expected reply error, got {:?}", other),
    }
}

#[test]
fn decode_query_with_domains_rejects_empty_subdomain_on_overlap() {
    let qname = "aa.example.com.";
    let query = encode_query(&QueryParams {
        id: 100,
        qname,
        qtype: RR_TXT,
        qclass: CLASS_IN,
        rd: true,
        cd: false,
        qdcount: 1,
        is_query: true,
    })
    .expect("encode query");

    match decode_query_with_domains(&query, &["aa.example.com", "example.com"]) {
        Err(DecodeQueryError::Reply { rcode, .. }) => {
            assert_eq!(rcode, Rcode::NameError);
        }
        other => panic!("expected name error, got {:?}", other),
    }
}
