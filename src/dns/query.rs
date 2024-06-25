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
