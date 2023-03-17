use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use pnet::datalink::{self, NetworkInterface};
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::echo_reply::EchoReplyPacket;
use pnet::packet::icmp::{IcmpPacket, IcmpType, MutableIcmpPacket};
use pnet::packet::Packet;
use pnet::packet::tcp::{self, MutableTcpPacket, TcpFlags};
use pnet::packet::udp::{self, MutableUdpPacket};
use pnet::packet::{MutablePacket, PacketSize};
use pnet::transport::{self, TransportChannelType, TransportProtocol};
use tokio::time::delay_for;

const SCAN_TIMEOUT: u64 = 2000; // in milliseconds

fn main() {
    let interface_name = "eth0";
    let interface = get_interface_by_name(interface_name).expect("Failed to get interface");
    let ip_addrs = get_ip_addrs(&interface).expect("Failed to get IP addresses");
    let ip_addrs = ip_addrs.iter().filter(|&ip| ip.is_ipv4()).map(|ip| ip.ip()).collect::<Vec<Ipv4Addr>>();

    let mut tasks = vec![];
    for ip_addr in ip_addrs {
        tasks.push(tokio::spawn(scan_ip(ip_addr)));
    }

    tokio::run(async move {
        for task in tasks {
            match task.await {
                Ok(result) => println!("{}", result),
                Err(e) => println!("Error: {:?}", e),
            }
        }
    });
}

fn get_interface_by_name(interface_name: &str) -> Option<NetworkInterface> {
    datalink::interfaces().into_iter().find(|iface| iface.name == interface_name)
}

fn get_ip_addrs(interface: &NetworkInterface) -> Option<Vec<IpAddr>> {
    interface.ips.iter().map(|ip| Some(ip.ip())).collect()
}

async fn scan_ip(ip_addr: Ipv4Addr) -> String {
    let (mut tx, mut rx) = transport::transport_channel(1024, TransportChannelType::Layer4(TransportProtocol::Tcp))
        .expect("Failed to create transport channel");

    let scan_task = tokio::spawn(async move {
        let mut tcp_packet = MutableTcpPacket::new(&mut [0u8; 20]).unwrap();
        tcp_packet.set_source(1234);
        tcp_packet.set_destination(80);
        tcp_packet.set_flags(TcpFlags::SYN);
        tcp_packet.set_sequence(0);
        tcp_packet.set_window(1024);

        let mut udp_packet = MutableUdpPacket::new(&mut [0u8; 8]).unwrap();
        udp_packet.set_source(1234);
        udp_packet.set_destination(80);

        let mut echo_packet = MutableEchoRequestPacket::new(&mut [0u8; 8]).unwrap();
        echo_packet.set_sequence_number(1234);

        let mut icmp_packet = MutableIcmpPacket::new(&mut [0u8; 8]).unwrap();
        icmp_packet.set_icmp_type(IcmpType(8)); // Echo Request
        icmp_packet.set_icmp_code(0);
        icmp_packet.set_sequence_number(1234);

        let mut buf = [0u8; 1024];
        tx.send_to(tcp_packet.packet(), IpAddr::V4(ip_addr)).unwrap();
        tx.send_to(udp_packet.packet(), IpAddr::V4(ip_addr)).unwrap();
        tx.send_to(echo_packet.packet(), Ip
