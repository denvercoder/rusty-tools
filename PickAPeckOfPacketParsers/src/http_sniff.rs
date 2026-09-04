/// Looks for a plaintext HTTP request/status line at the start of a TCP
/// payload and, if found, returns it along with the Host header (if any).
/// Uses a lossy UTF-8 conversion since a payload can mix ASCII headers with
/// a binary body in the same segment.
pub fn sniff_http(payload: &[u8]) -> Option<String> {
    if payload.is_empty() {
        return None;
    }

    let text = String::from_utf8_lossy(payload);
    let first_line = text.lines().next()?;

    const PREFIXES: &[&str] = &[
        "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "HTTP/",
    ];
    if !PREFIXES.iter().any(|prefix| first_line.starts_with(prefix)) {
        return None;
    }

    let host = text
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("host:"))
        .map(str::trim);

    Some(match host {
        Some(host_line) => format!("{}  {}", first_line.trim(), host_line),
        None => first_line.trim().to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_request_line_and_host() {
        let payload = b"GET /path HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl\r\n\r\n";
        assert_eq!(
            sniff_http(payload).as_deref(),
            Some("GET /path HTTP/1.1  Host: example.com")
        );
    }

    #[test]
    fn extracts_status_line_without_host() {
        let payload = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(sniff_http(payload).as_deref(), Some("HTTP/1.1 200 OK"));
    }

    #[test]
    fn ignores_non_http_payload() {
        let payload = b"\x16\x03\x01\x02\x00not http at all";
        assert_eq!(sniff_http(payload), None);
    }

    #[test]
    fn ignores_empty_payload() {
        assert_eq!(sniff_http(b""), None);
    }
}
