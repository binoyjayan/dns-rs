#[derive(Debug)]
/// DNS Header
/// 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                      ID                       |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    QDCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    ANCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    NSCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    ARCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

pub(crate) struct DnsHeader {
    id: u16,      // identification number
    flags: u16,   // flags - qr, opcode, aa, tc, rd, ra, z, rcode
    qdcount: u16, // number of question entries
    ancount: u16, // number of answer entries
    nscount: u16, // number of authority entries
    arcount: u16, // number of resource entries
}

impl DnsHeader {
    pub(crate) fn new(id: u16) -> DnsHeader {
        DnsHeader {
            id,
            flags: 0,
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
    }
    pub(crate) fn set_qr(&mut self, qr: bool) {
        self.flags = (self.flags & !(1 << 15)) | ((qr as u16) << 15);
    }

    #[allow(unused)]
    pub(crate) fn set_opcode(&mut self, opcode: u8) {
        self.flags = (self.flags & !(0b1111 << 11)) | ((opcode as u16) << 11);
    }

    pub(crate) fn set_aa(&mut self, aa: bool) {
        self.flags = (self.flags & !(1 << 10)) | ((aa as u16) << 10);
    }

    pub(crate) fn set_tc(&mut self, tc: bool) {
        self.flags = (self.flags & !(1 << 9)) | ((tc as u16) << 9);
    }

    pub(crate) fn set_rd(&mut self, rd: bool) {
        self.flags = (self.flags & !(1 << 8)) | ((rd as u16) << 8);
    }

    pub(crate) fn set_ra(&mut self, ra: bool) {
        self.flags = (self.flags & !(1 << 7)) | ((ra as u16) << 7);
    }

    pub(crate) fn set_z(&mut self, z: u8) {
        self.flags = (self.flags & !(0b111 << 4)) | ((z as u16) << 4);
    }

    pub(crate) fn set_rcode(&mut self, rcode: u8) {
        self.flags = (self.flags & !(0b1111)) | rcode as u16;
    }

    pub(crate) fn set_qdcount(&mut self, qdcount: u16) {
        self.qdcount = qdcount;
    }

    pub(crate) fn set_ancount(&mut self, count: u16) {
        self.ancount = count;
    }

    pub(crate) fn set_nscount(&mut self, count: u16) {
        self.nscount = count;
    }

    pub(crate) fn set_arcount(&mut self, count: u16) {
        self.arcount = count;
    }
}

impl From<&DnsHeader> for Vec<u8> {
    fn from(hdr: &DnsHeader) -> Self {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&hdr.id.to_be_bytes());
        bytes.extend_from_slice(&hdr.flags.to_be_bytes());
        bytes.extend_from_slice(&hdr.qdcount.to_be_bytes());
        bytes.extend_from_slice(&hdr.ancount.to_be_bytes());
        bytes.extend_from_slice(&hdr.nscount.to_be_bytes());
        bytes.extend_from_slice(&hdr.arcount.to_be_bytes());
        bytes
    }
}
