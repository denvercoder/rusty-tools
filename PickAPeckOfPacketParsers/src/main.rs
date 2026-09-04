mod dns;
mod http_sniff;
mod pcap_writer;
mod security;

use clap::{Parser, ValueEnum};
use pcap_writer::PcapWriter;
use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use security::{ArpSpoofTracker, PortScanTracker};
use std::net::IpAddr;
use std::path::PathBuf;
use std::process;

/// PickAPeckOfPacketParsers (4P) — live packet capture and parsing.
///
/// Run with `--list` to see available interfaces, or give one to start
/// capturing.
#[derive(Parser)]
#[command(name = "pppp", about = "Live packet capture and parsing")]
struct Cli {
    /// List available network interfaces and exit
    #[arg(short, long)]
    list: bool,

    /// Interface to capture on (e.g. eth0, wlan0)
    interface: Option<String>,

    /// Only show this protocol
    #[arg(long, value_enum, default_value_t = ProtoFilter::All)]
    protocol: ProtoFilter,

    /// Only show packets involving this port (TCP/UDP source or destination)
    #[arg(long)]
    port: Option<u16>,

    /// Only show packets involving this host (source or destination IP)
    #[arg(long)]
    host: Option<IpAddr>,

    /// Save the (filtered) capture to a .pcap file, openable in Wireshark
    #[arg(long)]
    pcap_out: Option<PathBuf>,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, ValueEnum)]
enum ProtoFilter {
    All,
    Tcp,
    Udp,
    Icmp,
    Arp,
}

struct Filter {
    protocol: ProtoFilter,
    port: Option<u16>,
    host: Option<IpAddr>,
}

impl Filter {
    /// `proto: None` means "doesn't belong to any of the filterable
    /// protocol categories" (e.g. a non-IP ethertype) — such packets only
    /// pass when the user hasn't restricted the protocol filter at all.
    fn matches(&self, proto: Option<ProtoFilter>, ports: &[u16], hosts: &[IpAddr]) -> bool {
        let proto_ok = match (self.protocol, proto) {
            (ProtoFilter::All, _) => true,
            (want, Some(actual)) => want == actual,
            (_, None) => false,
        };
        if !proto_ok {
            return false;
        }

        if let Some(want_port) = self.port {
            if !ports.contains(&want_port) {
                return false;
            }
        }

        if let Some(want_host) = self.host {
            if !hosts.contains(&want_host) {
                return false;
            }
        }

        true
    }
}

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

fn handle_ipv4(ipv4: &Ipv4Packet, filter: &Filter, port_scan: &mut PortScanTracker) -> bool {
    let src = ipv4.get_source();
    let dst = ipv4.get_destination();

    match ipv4.get_next_level_protocol() {
        IpNextHeaderProtocols::Tcp => {
            let Some(tcp) = TcpPacket::new(ipv4.payload()) else {
                return false;
            };
            let sp = tcp.get_source();
            let dp = tcp.get_destination();
            if !filter.matches(Some(ProtoFilter::Tcp), &[sp, dp], &[IpAddr::V4(src), IpAddr::V4(dst)]) {
                return false;
            }

            if let Some(alert) = port_scan.check(IpAddr::V4(src), dp) {
                println!("{}", alert);
            }

            let payload = tcp.payload();
            if sp == 80 || dp == 80 {
                if let Some(http_line) = http_sniff::sniff_http(payload) {
                    println!("HTTP   {}:{} -> {}:{}  {}", src, sp, dst, dp, http_line);
                    return true;
                }
            }
            println!(
                "TCP    {}:{} -> {}:{}  flags={:#04x}  {} bytes",
                src, sp, dst, dp, tcp.get_flags(), payload.len()
            );
            true
        }
        IpNextHeaderProtocols::Udp => {
            let Some(udp) = UdpPacket::new(ipv4.payload()) else {
                return false;
            };
            let sp = udp.get_source();
            let dp = udp.get_destination();
            if !filter.matches(Some(ProtoFilter::Udp), &[sp, dp], &[IpAddr::V4(src), IpAddr::V4(dst)]) {
                return false;
            }

            let payload = udp.payload();
            if sp == 53 || dp == 53 {
                if let Some(info) = dns::parse_dns(payload) {
                    println!(
                        "DNS    {}  {}  ({})",
                        if info.is_response { "response" } else { "query" },
                        info.name,
                        info.qtype
                    );
                    return true;
                }
            }
            println!("UDP    {}:{} -> {}:{}  {} bytes", src, sp, dst, dp, payload.len());
            true
        }
        IpNextHeaderProtocols::Icmp => {
            if !filter.matches(Some(ProtoFilter::Icmp), &[], &[IpAddr::V4(src), IpAddr::V4(dst)]) {
                return false;
            }
            let Some(icmp) = IcmpPacket::new(ipv4.payload()) else {
                return false;
            };
            println!("ICMP   {} -> {}  type={:?}", src, dst, icmp.get_icmp_type());
            true
        }
        other => {
            if !filter.matches(None, &[], &[IpAddr::V4(src), IpAddr::V4(dst)]) {
                return false;
            }
            println!("IPv4   {} -> {}  protocol={:?}", src, dst, other);
            true
        }
    }
}

fn handle_ipv6(ipv6: &Ipv6Packet, filter: &Filter, port_scan: &mut PortScanTracker) -> bool {
    let src = ipv6.get_source();
    let dst = ipv6.get_destination();

    match ipv6.get_next_header() {
        IpNextHeaderProtocols::Tcp => {
            let Some(tcp) = TcpPacket::new(ipv6.payload()) else {
                return false;
            };
            let sp = tcp.get_source();
            let dp = tcp.get_destination();
            if !filter.matches(Some(ProtoFilter::Tcp), &[sp, dp], &[IpAddr::V6(src), IpAddr::V6(dst)]) {
                return false;
            }

            if let Some(alert) = port_scan.check(IpAddr::V6(src), dp) {
                println!("{}", alert);
            }

            let payload = tcp.payload();
            if sp == 80 || dp == 80 {
                if let Some(http_line) = http_sniff::sniff_http(payload) {
                    println!("HTTP   [{}]:{} -> [{}]:{}  {}", src, sp, dst, dp, http_line);
                    return true;
                }
            }
            println!(
                "TCP    [{}]:{} -> [{}]:{}  flags={:#04x}  {} bytes",
                src, sp, dst, dp, tcp.get_flags(), payload.len()
            );
            true
        }
        IpNextHeaderProtocols::Udp => {
            let Some(udp) = UdpPacket::new(ipv6.payload()) else {
                return false;
            };
            let sp = udp.get_source();
            let dp = udp.get_destination();
            if !filter.matches(Some(ProtoFilter::Udp), &[sp, dp], &[IpAddr::V6(src), IpAddr::V6(dst)]) {
                return false;
            }

            let payload = udp.payload();
            if sp == 53 || dp == 53 {
                if let Some(info) = dns::parse_dns(payload) {
                    println!(
                        "DNS    {}  {}  ({})",
                        if info.is_response { "response" } else { "query" },
                        info.name,
                        info.qtype
                    );
                    return true;
                }
            }
            println!("UDP    [{}]:{} -> [{}]:{}  {} bytes", src, sp, dst, dp, payload.len());
            true
        }
        IpNextHeaderProtocols::Icmpv6 => {
            if !filter.matches(Some(ProtoFilter::Icmp), &[], &[IpAddr::V6(src), IpAddr::V6(dst)]) {
                return false;
            }
            let Some(icmp) = Icmpv6Packet::new(ipv6.payload()) else {
                return false;
            };
            println!("ICMPv6 [{}] -> [{}]  type={:?}", src, dst, icmp.get_icmpv6_type());
            true
        }
        other => {
            if !filter.matches(None, &[], &[IpAddr::V6(src), IpAddr::V6(dst)]) {
                return false;
            }
            println!("IPv6   [{}] -> [{}]  protocol={:?}", src, dst, other);
            true
        }
    }
}

fn handle_arp(eth: &EthernetPacket, filter: &Filter, arp_spoof: &mut ArpSpoofTracker) -> bool {
    let Some(arp) = ArpPacket::new(eth.payload()) else {
        return false;
    };
    let sender_ip = arp.get_sender_proto_addr();

    if !filter.matches(Some(ProtoFilter::Arp), &[], &[IpAddr::V4(sender_ip)]) {
        return false;
    }

    let sender_mac = arp.get_sender_hw_addr();
    if let Some(alert) = arp_spoof.check(sender_ip, sender_mac) {
        println!("{}", alert);
    }

    println!("ARP    {} is at {}", sender_ip, sender_mac);
    true
}

/// Parses one raw Ethernet frame, applying `filter` and printing anything
/// that passes. Returns whether the frame matched (and was printed), so the
/// caller knows whether to also write it to a pcap file. Kept separate from
/// the live-capture loop below so the same parsing path can later be fed
/// frames read from a saved .pcap file instead of a live interface.
fn parse_ethernet_frame(
    data: &[u8],
    filter: &Filter,
    port_scan: &mut PortScanTracker,
    arp_spoof: &mut ArpSpoofTracker,
) -> bool {
    let Some(eth) = EthernetPacket::new(data) else {
        return false;
    };

    match eth.get_ethertype() {
        EtherTypes::Ipv4 => match Ipv4Packet::new(eth.payload()) {
            Some(ipv4) => handle_ipv4(&ipv4, filter, port_scan),
            None => false,
        },
        EtherTypes::Ipv6 => match Ipv6Packet::new(eth.payload()) {
            Some(ipv6) => handle_ipv6(&ipv6, filter, port_scan),
            None => false,
        },
        EtherTypes::Arp => handle_arp(&eth, filter, arp_spoof),
        other => {
            if !filter.matches(None, &[], &[]) {
                return false;
            }
            println!(
                "{:?}  {} -> {}  {} bytes",
                other,
                eth.get_source(),
                eth.get_destination(),
                data.len()
            );
            true
        }
    }
}

fn capture(interface_name: &str, filter: Filter, pcap_out: Option<PathBuf>) {
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

    let mut pcap_writer = pcap_out.map(|path| match PcapWriter::create(&path) {
        Ok(writer) => {
            println!("Saving capture to {}", path.display());
            Some(writer)
        }
        Err(err) => {
            println!("Failed to open pcap output '{}': {}", path.display(), err);
            None
        }
    }).flatten();

    let mut port_scan = PortScanTracker::new();
    let mut arp_spoof = ArpSpoofTracker::new();

    println!("Listening on {}... (Ctrl+C to stop)", interface_name);

    loop {
        match rx.next() {
            Ok(frame) => {
                let matched = parse_ethernet_frame(frame, &filter, &mut port_scan, &mut arp_spoof);
                if matched {
                    if let Some(writer) = pcap_writer.as_mut() {
                        if let Err(err) = writer.write_packet(frame) {
                            println!("Failed to write to pcap file: {}", err);
                        }
                    }
                }
            }
            Err(err) => {
                println!("Error reading packet: {}", err);
                break;
            }
        }
    }
}

fn main() {
    let cli = Cli::parse();

    if cli.list {
        list_interfaces();
        return;
    }

    let Some(interface) = cli.interface else {
        list_interfaces();
        println!();
        println!("Usage: pppp <interface> [--protocol tcp|udp|icmp|arp] [--port N] [--host IP] [--pcap-out FILE]");
        println!("       pppp --list");
        return;
    };

    let filter = Filter {
        protocol: cli.protocol,
        port: cli.port,
        host: cli.host,
    };

    capture(&interface, filter, cli.pcap_out);
}
