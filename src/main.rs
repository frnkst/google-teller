use std::{thread };
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::str::FromStr;

use cidr_utils::cidr::IpCidr;
use etherparse::{ IpHeader, Ipv4Header, PacketHeaders };
use pcap::{Capture};
use rodio::{Decoder, OutputStream, source::Source};

fn main() {
    let ip_ranges = get_all_ip_ranges();

    let mut cap = Capture::from_device("en0").unwrap()
        .open().unwrap();

    while let Ok(packet) = cap.next_packet() {
        match PacketHeaders::from_ethernet_slice(&packet) {
            Err(_) => (),
            Ok(value) => {
                match value.ip {
                    Some(IpHeader::Version4(value, ..)) => check_packet(&ip_ranges, value),
                    Some(IpHeader::Version6(value, ..)) => println!("Handle ipv6: {:?}", value),
                    None => (),
                }
            }
        }
    }
}

fn get_all_ip_ranges() -> Vec<IpCidr> {
    let mut vec = Vec::new();

    let reader = BufReader::new(File::open("src/google-cidr-ranges.txt").expect("Cannot open file.txt"));
    for line in reader.lines() {
        if let Ok(l) = line {
            let ipcidr = IpCidr::from_str(&l.trim()).unwrap();
            vec.push(ipcidr);
        }
    }
    vec
}

fn check_packet(cidr: &Vec<IpCidr>, value: Ipv4Header) {
    let destination = value.destination.map(|i| i.to_string()).join(".");
    let destination_ip = IpAddr::from_str(&destination).unwrap();

    for cid in cidr.iter() {
        if cid.contains(destination_ip) {
            println!("google ip is: {}", &destination_ip);
            beep();
        }
    }
}

fn beep() {
    thread::spawn(|| {
        let (_stream, stream_handle) = OutputStream::try_default().unwrap();
        let file = BufReader::new(File::open("src/tone.mp3").unwrap());
        let source = Decoder::new(file).unwrap();
        stream_handle.play_raw(source.convert_samples()).expect("TODO: panic message");
        thread::sleep(std::time::Duration::from_millis(10));
    });
}

