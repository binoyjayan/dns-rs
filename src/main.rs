use std::net::UdpSocket;

mod dns;

use dns::{header::parse_header, header::DnsHeader, query::parse_query};

fn main() -> anyhow::Result<()> {
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];
    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                let buf = &buf[..size];
                let dnsreq = parse_header(buf)?;
                let req_id = dnsreq.get_id();
                let req_opcode = dnsreq.get_opcode();
                let req_rd = dnsreq.get_rd();
                let req_qdcount = dnsreq.get_qdcount();

                // Create a DNS response header
                let mut dns = DnsHeader::new(req_id);
                dns.set_qr(true);
                dns.set_opcode(req_opcode);
                dns.set_aa(false);
                dns.set_tc(false);
                dns.set_rd(req_rd);
                dns.set_ra(false);
                dns.set_z(0);
                // 0 if no error, 4 if not implemented
                let rcode = if req_opcode == 0 { 0 } else { 4 };
                dns.set_rcode(rcode);
                dns.set_qdcount(req_qdcount);
                dns.set_ancount(req_qdcount);
                dns.set_nscount(0);
                dns.set_arcount(0);

                // Write the DNS header to the response
                let mut packet: Vec<u8> = Vec::from(&dns);
                let mut ans: Vec<u8> = Vec::new();
                let mut offset = DnsHeader::SIZE;

                // Write responses for all the queries
                while offset < size {
                    let dnsquery = parse_query(buf, offset)?;
                    let qname = dnsquery.qname;

                    // DNS Query section
                    packet.extend_from_slice(&qname);
                    packet.extend_from_slice(&1u16.to_be_bytes()); // DNS type A
                    packet.extend_from_slice(&1u16.to_be_bytes()); // class IN

                    // DNS Answer section
                    ans.extend_from_slice(&qname);
                    ans.extend_from_slice(&1u16.to_be_bytes()); // DNS type A
                    ans.extend_from_slice(&1u16.to_be_bytes()); // class IN
                    ans.extend_from_slice(&60u32.to_be_bytes()); // TTL
                    ans.extend_from_slice(&4u16.to_be_bytes()); // rdata length
                    ans.extend_from_slice(&[8, 8, 8, 8]); // rdata

                    offset = dnsquery.pos;
                }

                // Extend the packet with the answer section
                packet.extend_from_slice(&ans);

                udp_socket
                    .send_to(&packet, source)
                    .expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
    Ok(())
}
