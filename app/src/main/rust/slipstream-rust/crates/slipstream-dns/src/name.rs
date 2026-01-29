use crate::types::{DnsError, Rcode};

pub(crate) const MAX_DNS_NAME_LEN: usize = 253;

fn extract_subdomain(qname: &str, domain: &str) -> Result<String, Rcode> {
    let domain = domain.trim_end_matches('.');
    if domain.is_empty() {
        return Err(Rcode::NameError);
    }

    let suffix = format!(".{}.", domain);
    if !qname
        .to_ascii_lowercase()
        .ends_with(&suffix.to_ascii_lowercase())
    {
        return Err(Rcode::NameError);
    }

    if qname.len() <= domain.len() + 2 {
        return Err(Rcode::NameError);
    }

    let data_len = qname.len() - domain.len() - 2;
    let subdomain = &qname[..data_len];
    if subdomain.is_empty() {
        return Err(Rcode::NameError);
    }
    Ok(subdomain.to_string())
}

pub(crate) fn extract_subdomain_multi(qname: &str, domains: &[&str]) -> Result<String, Rcode> {
    let qname_trimmed = qname.trim_end_matches('.');
    if qname_trimmed.is_empty() {
        return Err(Rcode::NameError);
    }
    let qname_lower = qname_trimmed.to_ascii_lowercase();

    let mut best_domain: Option<&str> = None;
    let mut best_len = 0usize;
    let mut best_empty = false;

    for domain in domains {
        let domain_trimmed = domain.trim_end_matches('.');
        if domain_trimmed.is_empty() {
            continue;
        }
        let domain_lower = domain_trimmed.to_ascii_lowercase();

        let is_exact = qname_lower == domain_lower;
        let is_suffix = !is_exact
            && qname_lower.len() > domain_lower.len()
            && qname_lower.ends_with(&domain_lower)
            && qname_lower.as_bytes()[qname_lower.len() - domain_lower.len() - 1] == b'.';

        if !is_exact && !is_suffix {
            continue;
        }

        let domain_len = domain_trimmed.len();
        if domain_len > best_len {
            best_len = domain_len;
            best_domain = Some(domain_trimmed);
            best_empty = is_exact;
        }
    }

    let Some(best_domain) = best_domain else {
        return Err(Rcode::NameError);
    };
    if best_empty {
        return Err(Rcode::NameError);
    }

    extract_subdomain(qname, best_domain)
}

pub(crate) fn parse_name(packet: &[u8], start: usize) -> Result<(String, usize), DnsError> {
    let mut labels = Vec::new();
    let mut offset = start;
    let mut jumped = false;
    let mut end_offset = start;
    let mut seen = Vec::new();
    let mut depth = 0usize;
    let mut name_len = 0usize;

    loop {
        if offset >= packet.len() {
            return Err(DnsError::new("name out of range"));
        }
        let len = packet[offset];
        if len & 0xC0 == 0xC0 {
            if offset + 1 >= packet.len() {
                return Err(DnsError::new("truncated pointer"));
            }
            let ptr = (((len & 0x3F) as usize) << 8) | packet[offset + 1] as usize;
            if ptr >= packet.len() {
                return Err(DnsError::new("pointer out of range"));
            }
            if seen.contains(&ptr) {
                return Err(DnsError::new("pointer loop"));
            }
            seen.push(ptr);
            if !jumped {
                end_offset = offset + 2;
                jumped = true;
            }
            offset = ptr;
            depth += 1;
            if depth > 16 {
                return Err(DnsError::new("pointer depth exceeded"));
            }
            continue;
        }
        if len == 0 {
            offset += 1;
            if !jumped {
                end_offset = offset;
            }
            break;
        }
        if len > 63 {
            return Err(DnsError::new("label too long"));
        }
        offset += 1;
        let end = offset + len as usize;
        if end > packet.len() {
            return Err(DnsError::new("label out of range"));
        }
        if !labels.is_empty() {
            name_len += 1;
        }
        name_len += len as usize;
        if name_len > MAX_DNS_NAME_LEN {
            return Err(DnsError::new("name too long"));
        }
        let label = std::str::from_utf8(&packet[offset..end])
            .map_err(|_| DnsError::new("label not utf-8"))?;
        labels.push(label.to_string());
        offset = end;
        if !jumped {
            end_offset = offset;
        }
    }

    let name = if labels.is_empty() {
        ".".to_string()
    } else {
        let mut name = labels.join(".");
        name.push('.');
        name
    };

    Ok((name, end_offset))
}

pub(crate) fn encode_name(name: &str, out: &mut Vec<u8>) -> Result<(), DnsError> {
    if name == "." {
        out.push(0);
        return Ok(());
    }

    let trimmed = name.trim_end_matches('.');
    let mut name_len = 0usize;
    let mut first = true;
    for label in trimmed.split('.') {
        if label.is_empty() {
            return Err(DnsError::new("empty label"));
        }
        if label.len() > 63 {
            return Err(DnsError::new("label too long"));
        }
        if !first {
            name_len += 1;
        }
        name_len += label.len();
        if name_len > MAX_DNS_NAME_LEN {
            return Err(DnsError::new("name too long"));
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
        first = false;
    }
    out.push(0);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::MAX_DNS_NAME_LEN;
    use super::{encode_name, parse_name};

    fn build_name(last_label_len: usize) -> String {
        format!(
            "{}.{}.{}.{}.",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(last_label_len)
        )
    }

    #[test]
    fn encode_name_rejects_long_name() {
        let mut out = Vec::new();
        let max_name = build_name(61);
        assert!(max_name.trim_end_matches('.').len() == MAX_DNS_NAME_LEN);
        assert!(encode_name(&max_name, &mut out).is_ok());

        let mut out = Vec::new();
        let too_long = build_name(62);
        assert!(encode_name(&too_long, &mut out).is_err());
    }

    #[test]
    fn parse_name_rejects_long_name() {
        let mut packet = Vec::new();
        let labels = [63usize, 63, 63, 61];
        for len in labels {
            packet.push(len as u8);
            packet.extend(std::iter::repeat_n(b'a', len));
        }
        packet.push(0);
        assert!(parse_name(&packet, 0).is_ok());

        let mut packet = Vec::new();
        let labels = [63usize, 63, 63, 62];
        for len in labels {
            packet.push(len as u8);
            packet.extend(std::iter::repeat_n(b'a', len));
        }
        packet.push(0);
        assert!(parse_name(&packet, 0).is_err());
    }
}
