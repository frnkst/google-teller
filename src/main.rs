use etherparse::InternetSlice::Ipv4;
use etherparse::{InternetSlice, IpHeader, PacketHeaders, SlicedPacket};
use pcap::{Capture, Device};
use rodio::{Sink};
use std::{thread, time};
use std::fs::File;
use std::io::BufReader;
use rodio::{Decoder, OutputStream, source::Source};

fn play_sound() {
    let (_stream, stream_handle) = OutputStream::try_default().unwrap();
    let file = BufReader::new(File::open("src/tone.mp3").unwrap());
    let source = Decoder::new(file).unwrap();
    stream_handle.play_raw(source.convert_samples());

// The sound plays in a separate audio thread,
// so we need to keep the main thread alive while it's playing.
    std::thread::sleep(std::time::Duration::from_secs(5));
}


fn main() {
    play_sound();

    let devices = Device::list().unwrap();


    println!("requested_device : {:?}", devices);
    let mut cap = Capture::from_device("en0").unwrap()
        .open().unwrap();

    while let Ok(packet) = cap.next_packet() {
        // println!("received packet!");
        // println!("{:?}", &packet.data);

        match PacketHeaders::from_ethernet_slice(&packet) {
            Err(value) => println!("Err {:?}", value),
            Ok(value) => {
                // println!("link: {:?}", value.link);
                // println!("vlan: {:?}", value.vlan);
                // println!("ip: {:?}", value.ip);

                match value.ip {
                    Some(IpHeader::Version4(value, ..)) => {
                        let a = value.destination.map(|d| d.to_string()).join(".");

                        // let s = match String::from_utf8_lossy(&value.destination) {
                        //     Ok(v) => v,
                        //     Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
                        // };

                        // println!("s is {}", a.to_string());

                        if  a.to_string().eq("62.2.24.158") {
                            println!("got a hit!");
                            play_sound();
                        }

                    },
                    Some(IpHeader::Version6(value, ..)) => {
                        println!("nothing: {:?}", value);
                    },
                    None => println!("Error"),
                }


                // println!("transport: {:?}", value.transport);
            }
        }

    }


}
