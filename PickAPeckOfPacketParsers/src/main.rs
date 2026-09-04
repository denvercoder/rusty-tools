use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::env;
use std::process;

fn list_interfaces() {
    println!("Available interfaces:");
    for iface in datalink::interfaces() {
        let state = if iface.is_up() { "UP" } else { "DOWN" };
        let desc = if iface.description.is_empty() {
            String::new()
        } else {
            format!(" — {}", iface.description)
        };
        println!("  {:<12} {}{}", iface.name, state, desc);
    }
}

fn print_ipv4(ipv4: &Ipv4Packet) {
    let src = ipv4.get_source();
    let dst = ipv4.get_destination();

    match ipv4.get_next_level_protocol() {
        IpNextHeaderProtocols::Tcp => {
            if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                println!(
                    "TCP    {}:{} -> {}:{}  flags={:#04x}  {} bytes",
                    src,
                    tcp.get_source(),
                    dst,
                    tcp.get_destination(),
                    tcp.get_flags(),
                    ipv4.payload().len()
                );
            }
        }
        IpNextHeaderProtocols::Udp => {
            if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                println!(
                    "UDP    {}:{} -> {}:{}  {} bytes",
                    src,
                    udp.get_source(),
                    dst,
                    udp.get_destination(),
                    udp.payload().len()
                );
            }
        }
        IpNextHeaderProtocols::Icmp => {
            if let Some(icmp) = IcmpPacket::new(ipv4.payload()) {
                println!(
                    "ICMP   {} -> {}  type={:?}",
                    src,
                    dst,
                    icmp.get_icmp_type()
                );
            }
        }
        other => println!("IPv4   {} -> {}  protocol={:?}", src, dst, other),
    }
}

fn print_ipv6(ipv6: &Ipv6Packet) {
    let src = ipv6.get_source();
    let dst = ipv6.get_destination();

    match ipv6.get_next_header() {
        IpNextHeaderProtocols::Tcp => {
            if let Some(tcp) = TcpPacket::new(ipv6.payload()) {
                println!(
                    "TCP    [{}]:{} -> [{}]:{}  flags={:#04x}  {} bytes",
                    src,
                    tcp.get_source(),
                    dst,
                    tcp.get_destination(),
                    tcp.get_flags(),
                    ipv6.payload().len()
                );
            }
        }
        IpNextHeaderProtocols::Udp => {
            if let Some(udp) = UdpPacket::new(ipv6.payload()) {
                println!(
                    "UDP    [{}]:{} -> [{}]:{}  {} bytes",
                    src,
                    udp.get_source(),
                    dst,
                    udp.get_destination(),
                    udp.payload().len()
                );
            }
        }
        IpNextHeaderProtocols::Icmpv6 => {
            if let Some(icmp) = Icmpv6Packet::new(ipv6.payload()) {
                println!(
                    "ICMPv6 [{}] -> [{}]  type={:?}",
                    src,
                    dst,
                    icmp.get_icmpv6_type()
                );
            }
        }
        other => println!("IPv6   [{}] -> [{}]  protocol={:?}", src, dst, other),
    }
}

/// Parses one raw Ethernet frame and prints its layers. Kept separate from
/// the live-capture loop below so the same parsing path can later be fed
/// frames read from a saved .pcap file instead of a live interface.
fn parse_ethernet_frame(data: &[u8]) {
    let Some(eth) = EthernetPacket::new(data) else {
        return;
    };

    match eth.get_ethertype() {
        EtherTypes::Ipv4 => {
            if let Some(ipv4) = Ipv4Packet::new(eth.payload()) {
                print_ipv4(&ipv4);
            }
        }
        EtherTypes::Ipv6 => {
            if let Some(ipv6) = Ipv6Packet::new(eth.payload()) {
                print_ipv6(&ipv6);
            }
        }
        EtherTypes::Arp => {
            println!(
                "ARP    {} -> {}",
                eth.get_source(),
                eth.get_destination()
            );
        }
        other => {
            println!(
                "{:?}  {} -> {}  {} bytes",
                other,
                eth.get_source(),
                eth.get_destination(),
                data.len()
            );
        }
    }
}

fn capture(interface_name: &str) {
    let interface = datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == interface_name);

    let Some(interface) = interface else {
        println!(
            "No such interface '{}'. Use --list to see available interfaces.",
            interface_name
        );
        process::exit(1);
    };

    let (_tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            println!("Unsupported channel type for interface '{}'.", interface_name);
            process::exit(1);
        }
        Err(err) => {
            println!("Failed to open interface '{}': {}", interface_name, err);
            println!(
                "Packet capture needs elevated privileges — try running with sudo, or grant \
                 the capability once: sudo setcap cap_net_raw+ep <path to binary>"
            );
            process::exit(1);
        }
    };

    println!("Listening on {}... (Ctrl+C to stop)", interface_name);

    loop {
        match rx.next() {
            Ok(frame) => parse_ethernet_frame(frame),
            Err(err) => {
                println!("Error reading packet: {}", err);
                break;
            }
        }
    }
}

fn print_usage(program: &str) {
    println!("Usage:");
    println!("  {} --list           List available network interfaces", program);
    println!("  {} <interface>      Capture and parse packets on an interface", program);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args.first().cloned().unwrap_or_else(|| "pppp".to_string());

    match args.get(1).map(String::as_str) {
        None | Some("-h") | Some("--help") => print_usage(&program),
        Some("--list") | Some("-l") => list_interfaces(),
        Some(interface) => capture(interface),
    }
}
