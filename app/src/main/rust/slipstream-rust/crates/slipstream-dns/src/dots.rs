pub fn dotify(input: &str) -> String {
    if input.is_empty() {
        return String::new();
    }

    let bytes = input.as_bytes();
    let len = bytes.len();
    let dots = (len - 1) / 57;
    let new_len = len + dots;

    let mut buf = Vec::with_capacity(new_len);
    buf.extend_from_slice(bytes);
    buf.resize(new_len, 0);

    let mut src = len as isize - 1;
    let mut dst = new_len as isize - 1;
    let mut next_dot = len - (len % 57);
    if len.is_multiple_of(57) {
        next_dot = len - 57;
    }
    let mut current_pos = len;

    while current_pos > 0 {
        if current_pos == next_dot {
            buf[dst as usize] = b'.';
            dst -= 1;
            next_dot = next_dot.saturating_sub(57);
            current_pos -= 1;
            continue;
        }

        buf[dst as usize] = buf[src as usize];
        dst -= 1;
        src -= 1;
        current_pos -= 1;
    }

    String::from_utf8(buf).unwrap_or_default()
}

pub fn undotify(input: &str) -> String {
    let mut out = Vec::with_capacity(input.len());
    for &b in input.as_bytes() {
        if b != b'.' {
            out.push(b);
        }
    }
    String::from_utf8(out).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::dotify;

    #[test]
    fn dotify_skips_trailing_dot_for_exact_segments() {
        let input = "A".repeat(57);
        let dotted = dotify(&input);
        assert_eq!(dotted, input);
        assert!(!dotted.ends_with('.'));
    }

    #[test]
    fn dotify_inserts_between_segments() {
        let input = "A".repeat(114);
        let dotted = dotify(&input);
        let expected = format!("{}.{}", "A".repeat(57), "A".repeat(57));
        assert_eq!(dotted, expected);
        assert!(!dotted.ends_with('.'));
    }
}
