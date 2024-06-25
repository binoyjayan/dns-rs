#[allow(dead_code)]
#[derive(Debug)]
/// DNS Query
pub(crate) struct DnsQuery {
    pub(crate) qname: Vec<u8>,
    pub(crate) name: String,
    pub(crate) qtype: u16,
    pub(crate) qclass: u16,
    pub(crate) size: usize,
}

impl DnsQuery {
    pub(crate) const PTR_MASK: u8 = 0b1100_0000;
}

impl<'a> TryFrom<&'a [u8]> for DnsQuery {
    type Error = std::array::TryFromSliceError;

    fn try_from(buf: &'a [u8]) -> Result<Self, Self::Error> {
        // Parse sequence of labels encoded as '<length><content>'
        let mut qname = Vec::new();
        let mut name = String::new();
        let mut pos = 0;
        while pos < buf.len() {
            let len = buf[pos];
            pos += 1;
            if len == 0 {
                qname.push(0);
                break;
            }
            let end = pos + len as usize;
            let label = &buf[pos..end];
            qname.push(len);
            qname.extend(label);
            name.push_str(&String::from_utf8_lossy(label));
            name.push('.');
            pos += len as usize;
        }
        name.pop(); // Remove the trailing '.'

        // Here we convert slices of the buffer into arrays for from_be_bytes.
        let qtype = u16::from_be_bytes(buf[pos..pos + 2].try_into().unwrap());
        pos += 2;
        let qclass = u16::from_be_bytes(buf[pos..pos + 2].try_into().unwrap());
        pos += 2;

        Ok(Self {
            qname,
            name,
            qtype,
            qclass,
            size: pos,
        })
    }
}

pub(crate) fn parse_query(buf: &[u8], offset: usize, size: usize) -> anyhow::Result<DnsQuery> {
    let data = &buf[offset..size];
    let len = data[0];
    // Check if the length is a pointer
    if len & DnsQuery::PTR_MASK == DnsQuery::PTR_MASK {
        // The length is a pointer to another offset in the packet
        // after clearing the two most significant bits
        let off = (len & !DnsQuery::PTR_MASK) as usize;
        return parse_query(buf, offset + off, size);
    }
    DnsQuery::try_from(data).map_err(|err| anyhow::anyhow!(err))
}
