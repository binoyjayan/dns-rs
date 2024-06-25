use std::net::UdpSocket;

mod dns;

use dns::{header::DnsHeader, query::DnsQuery};

fn convert_to_dns_header(buf: &[u8]) -> anyhow::Result<DnsHeader> {
    DnsHeader::try_from(buf).map_err(|err| anyhow::anyhow!(err))
}

fn convert_to_dns_query(buf: &[u8]) -> anyhow::Result<dns::query::DnsQuery> {
    DnsQuery::try_from(buf).map_err(|err| anyhow::anyhow!(err))
}

fn main() -> anyhow::Result<()> {
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];
    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                let dnsreq = convert_to_dns_header(&buf)?;
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
                let mut offset = DnsHeader::SIZE;

                println!(
                    "DNS request [ id: {}, opcode: {}, qdcount: {} size: {} ]",
                    req_id, req_opcode, req_qdcount, size,
                );

                // Write responses for all the queries
                while offset < size {
                    let data = &buf[offset..size];
                    let dnsquery = convert_to_dns_query(data)?;
                    let qname = dnsquery.qname;

                    // DNS Query section
                    packet.extend_from_slice(&qname);
                    packet.extend_from_slice(&1u16.to_be_bytes()); // DNS type A
                    packet.extend_from_slice(&1u16.to_be_bytes()); // class IN

                    // DNS Answer section
                    packet.extend_from_slice(&qname);
                    packet.extend_from_slice(&1u16.to_be_bytes()); // DNS type A
                    packet.extend_from_slice(&1u16.to_be_bytes()); // class IN
                    packet.extend_from_slice(&60u32.to_be_bytes()); // TTL
                    packet.extend_from_slice(&4u16.to_be_bytes()); // rdata length
                    packet.extend_from_slice(&[8, 8, 8, 8]); // rdata

                    offset += dnsquery.size;
                }

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
