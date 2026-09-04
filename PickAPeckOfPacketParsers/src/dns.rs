/// Minimal DNS message parser: just enough to report whether a UDP/53
/// packet is a query or response and what name/type the first question
/// asks about. Doesn't parse answer records or follow name compression
/// pointers (rare in question sections, which is all v1 looks at).
pub struct DnsInfo {
    pub is_response: bool,
    pub name: String,
    pub qtype: String,
}

pub fn parse_dns(payload: &[u8]) -> Option<DnsInfo> {
    if payload.len() < 12 {
        return None;
    }

    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let is_response = flags & 0x8000 != 0;
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    if qdcount == 0 {
        return None;
    }

    let mut pos = 12;
    let mut labels = Vec::new();
    loop {
        let len = *payload.get(pos)? as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            // Compressed name pointer — not handled in v1.
            return None;
        }
        pos += 1;
        let label = payload.get(pos..pos + len)?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        pos += len;
    }

    let qtype_bytes = payload.get(pos..pos + 2)?;
    let qtype_num = u16::from_be_bytes([qtype_bytes[0], qtype_bytes[1]]);
    let qtype = match qtype_num {
        1 => "A".to_string(),
        28 => "AAAA".to_string(),
        5 => "CNAME".to_string(),
        15 => "MX".to_string(),
        16 => "TXT".to_string(),
        2 => "NS".to_string(),
        12 => "PTR".to_string(),
        33 => "SRV".to_string(),
        other => format!("TYPE{}", other),
    };

    Some(DnsInfo {
        is_response,
        name: labels.join("."),
        qtype,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_query(name: &str, qtype: u16, is_response: bool) -> Vec<u8> {
        let flags: u16 = if is_response { 0x8180 } else { 0x0100 };
        let mut msg = vec![0x12, 0x34];
        msg.extend_from_slice(&flags.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes()); // qdcount
        msg.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // an/ns/arcount

        for label in name.split('.') {
            msg.push(label.len() as u8);
            msg.extend_from_slice(label.as_bytes());
        }
        msg.push(0); // root label
        msg.extend_from_slice(&qtype.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes()); // qclass IN

        msg
    }

    #[test]
    fn parses_a_query() {
        let msg = build_query("example.com", 1, false);
        let info = parse_dns(&msg).unwrap();
        assert!(!info.is_response);
        assert_eq!(info.name, "example.com");
        assert_eq!(info.qtype, "A");
    }

    #[test]
    fn parses_aaaa_response() {
        let msg = build_query("example.com", 28, true);
        let info = parse_dns(&msg).unwrap();
        assert!(info.is_response);
        assert_eq!(info.qtype, "AAAA");
    }

    #[test]
    fn unknown_qtype_falls_back_to_numeric() {
        let msg = build_query("example.com", 99, false);
        let info = parse_dns(&msg).unwrap();
        assert_eq!(info.qtype, "TYPE99");
    }

    #[test]
    fn rejects_truncated_payload() {
        assert!(parse_dns(&[0u8; 5]).is_none());
    }

    #[test]
    fn rejects_zero_questions() {
        let mut msg = vec![0x12, 0x34, 0x01, 0x00];
        msg.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]); // qdcount=0
        assert!(parse_dns(&msg).is_none());
    }
}
