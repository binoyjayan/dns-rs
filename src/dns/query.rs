use anyhow::Context;

#[allow(dead_code)]
#[derive(Debug)]
/// DNS Query
pub(crate) struct DnsQuery {
    pub(crate) qname: Vec<u8>,
    pub(crate) name: String,
    pub(crate) qtype: u16,
    pub(crate) qclass: u16,
    pub(crate) pos: usize,
}

impl DnsQuery {
    pub(crate) const PTR_MASK: u8 = 0b1100_0000;
}

pub(crate) fn parse_label_sequence(
    buf: &[u8],
    mut pos: usize,
) -> anyhow::Result<(Vec<u8>, String, usize)> {
    let mut qname = Vec::new();
    let mut name = String::new();
    let mut complete = false;
    while pos < buf.len() {
        let len = buf[pos];
        pos += 1;
        if len & DnsQuery::PTR_MASK == DnsQuery::PTR_MASK {
            // Two bytes pointer
            let pointer =
                ((len as usize & !(DnsQuery::PTR_MASK as usize)) << 8) | buf[pos] as usize;
            pos += 1;
            let (pqname, pname, _) = parse_label_sequence(buf, pointer)?;
            qname.extend(pqname);
            name.push_str(&pname);
            complete = true;
            break;
        } else if len == 0 {
            qname.push(0);
            complete = true;
            break;
        } else {
            let end = pos + len as usize;
            let label = &buf[pos..end];
            qname.push(len);
            qname.extend(label);
            name.push_str(&String::from_utf8_lossy(label));
            name.push('.');
            pos += len as usize;
        }
    }
    if !complete {
        return Err(anyhow::anyhow!("Incomplete label sequence"));
    }
    Ok((qname, name, pos))
}

pub(crate) fn parse_query(buf: &[u8], pos: usize) -> anyhow::Result<DnsQuery> {
    let (qname, name, mut pos) = parse_label_sequence(buf, pos)?;
    if pos + 4 > buf.len() {
        return Err(anyhow::anyhow!(format!(
            "Position exceeds buffer size ({} > {})",
            pos + 4,
            buf.len()
        )));
    }
    let qtype = u16::from_be_bytes(
        buf[pos..pos + 2]
            .try_into()
            .context("Failed to convert qtype")?,
    );
    pos += 2;
    let qclass = u16::from_be_bytes(
        buf[pos..pos + 2]
            .try_into()
            .context("Failed to convert qclass")?,
    );
    pos += 2;
    Ok(DnsQuery {
        qname,
        name,
        qtype,
        qclass,
        pos,
    })
}
