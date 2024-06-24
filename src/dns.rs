use std::convert::TryFrom;

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
    pub(crate) const QR_MASK: u16 = 0b1000_0000_0000_0000;
    pub(crate) const OPCODE_MASK: u16 = 0b0111_1000_0000_0000;
    pub(crate) const AA_MASK: u16 = 0b0000_0100_0000_0000;
    pub(crate) const TC_MASK: u16 = 0b0000_0010_0000_0000;
    pub(crate) const RD_MASK: u16 = 0b0000_0001_0000_0000;
    pub(crate) const RA_MASK: u16 = 0b0000_0000_1000_0000;
    pub(crate) const Z_MASK: u16 = 0b0000_0000_0111_0000;
    pub(crate) const RCODE_MASK: u16 = 0b0000_0000_0000_1111;

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
    pub(crate) fn get_id(&self) -> u16 {
        self.id
    }

    pub(crate) fn get_opcode(&self) -> u8 {
        ((self.flags & Self::OPCODE_MASK) >> 11) as u8
    }
    pub(crate) fn get_rd(&self) -> bool {
        ((self.flags & Self::RD_MASK) >> 8) == 1
    }

    pub(crate) fn set_qr(&mut self, qr: bool) {
        self.flags = (self.flags & !Self::QR_MASK) | ((qr as u16) << 15);
    }

    pub(crate) fn set_opcode(&mut self, opcode: u8) {
        self.flags = (self.flags & !Self::OPCODE_MASK) | ((opcode as u16) << 11);
    }

    pub(crate) fn set_aa(&mut self, aa: bool) {
        self.flags = (self.flags & !Self::AA_MASK) | ((aa as u16) << 10);
    }

    pub(crate) fn set_tc(&mut self, tc: bool) {
        self.flags = (self.flags & !Self::TC_MASK) | ((tc as u16) << 9);
    }

    pub(crate) fn set_rd(&mut self, rd: bool) {
        self.flags = (self.flags & !Self::RD_MASK) | ((rd as u16) << 8);
    }

    pub(crate) fn set_ra(&mut self, ra: bool) {
        self.flags = (self.flags & !Self::RA_MASK) | ((ra as u16) << 7);
    }

    pub(crate) fn set_z(&mut self, z: u8) {
        self.flags = (self.flags & !Self::Z_MASK) | ((z as u16) << 4);
    }

    pub(crate) fn set_rcode(&mut self, rcode: u8) {
        self.flags = (self.flags & !Self::RCODE_MASK) | rcode as u16;
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

impl<'a> TryFrom<&'a [u8]> for DnsHeader {
    type Error = std::array::TryFromSliceError;

    fn try_from(slice: &'a [u8]) -> Result<Self, Self::Error> {
        Ok(Self {
            id: u16::from_be_bytes(slice[0..2].try_into()?),
            flags: u16::from_be_bytes(slice[2..4].try_into()?),
            qdcount: u16::from_be_bytes(slice[4..6].try_into()?),
            ancount: u16::from_be_bytes(slice[6..8].try_into()?),
            nscount: u16::from_be_bytes(slice[8..10].try_into()?),
            arcount: u16::from_be_bytes(slice[10..12].try_into()?),
        })
    }
}
