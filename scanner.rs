use std::env;
use std::net::{IpAddr, Ipv4Addr};
use pnet::util::checksum;
use pnet::packet::icmp::echo_request::{MutableEchoRequestPacket, EchoRequestPacket};
use pnet::packet::icmp::{IcmpPacket, IcmpType};
use pnet::packet::ip::{IpNextHeaderProtocol, MutableIpv4Packet, Ipv4Packet};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::transport::{transport_channel, TransportChannelType::Layer4, icmp_packet_iter};
use pnet::transport::tcp_packet_iter;
use tokio::time::{timeout, Duration};

const TIMEOUT: Duration = Duration::from_secs(1);

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: {} <ip-range>", args[0]);
        std::process::exit(1);
    }

    let ip_range: &str = &args[1];
    let ips: Vec<Ipv4Addr> = ip_range.parse().unwrap();

    for ip in ips {
        let icmp_packet = create_icmp_packet(ip);
        let (mut tx, mut rx) = transport_channel(4096, Layer4(IpNextHeaderProtocol::Icmp)).unwrap();
        tx.send_to(icmp_packet, IpAddr::V4(ip)).unwrap();

        match timeout(TIMEOUT, icmp_packet_iter(&mut rx)).await {
            Ok(result) => {
                if let Some((_packet, addr)) = result {
                    println!("{} is online", addr);
                    scan_ports(addr).await;
                }
            }
            Err(_) => continue,
        }
    }
}

fn create_icmp_packet(ip: Ipv4Addr) -> MutableEchoRequestPacket {
    let mut icmp_buffer = [0u8; 64];
    let mut icmp_packet = MutableEchoRequestPacket::new(&mut icmp_buffer[..]).unwrap();

    icmp_packet.set_icmp_type(IcmpType::EchoRequest);
    icmp_packet.set_checksum(checksum(&IcmpPacket::new(&icmp_packet.packet()).unwrap()));
    icmp_packet.set_identifier(1);
    icmp_packet.set_sequence_number(1);

    icmp_packet
}

async fn scan_ports(ip: IpAddr) {
    let (mut tx, mut rx) = transport_channel(4096, Layer4(IpNextHeaderProtocol::Tcp)).unwrap();

    for port in 1..65535 {
        let tcp_packet = create_tcp_packet(ip, port);
        tx.send_to(tcp_packet, ip).unwrap();

        match timeout(TIMEOUT, tcp_packet_iter(&mut rx)).await {
            Ok(result) => {
                if let Some((_packet, _addr)) = result {
                    println!("{}:{} is open", ip, port);
                }
            }
            Err(_) => continue,
        }
    }
}

fn create_tcp_packet(ip: IpAddr, port: u16) -> MutableTcpPacket {
    let mut tcp_buffer = [0u8; 64];
    let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buffer[..]).unwrap();

    tcp_packet.set_source(1234);
    tcp_packet.set_destination(port);
    tcp_packet.set_flags(TcpFlags::SYN);
    tcp_packet.set_checksum(checksum(&TcpPacket::new(&tcp_packet.packet(), &Ipv4Packet::new(&[0u8; 20]).unwrap(), &[]).unwrap()));

    tcp_packet
}
