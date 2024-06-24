use std::net::UdpSocket;

mod dns;

fn main() {
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];
    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                let mut dns = dns::DnsHeader::new(1234);
                dns.set_qr(true);
                dns.set_aa(false);
                dns.set_tc(false);
                dns.set_rd(false);
                dns.set_ra(false);
                dns.set_z(0);
                dns.set_rcode(0);
                dns.set_qdcount(1);
                dns.set_ancount(0);
                dns.set_nscount(0);
                dns.set_arcount(0);

                let mut packet: Vec<u8> = Vec::from(&dns);
                // Create and set the resource record
                packet.extend_from_slice(b"\x0ccodecrafters\x02io\x00");
                // DNS type A and class IN
                packet.extend_from_slice(&1u16.to_be_bytes());
                packet.extend_from_slice(&1u16.to_be_bytes());
                let len = packet.len();
                println!("Received {} bytes from {}, sending {}", size, source, len);
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
}
