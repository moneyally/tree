//! A new device for manual device-link testing: prints its link (to paste or
//! show as a QR code), then the code once the existing device scanned it,
//! and confirms when told to.
//!   cargo run -p tree-client --example new_device -- <profile> <server> [yes|no]
use std::time::Duration;
use tree_client::{LinkStatus, Session};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (path, server) = (&args[1], &args[2]);
    let answer = args.get(3).map(|a| a == "yes").unwrap_or(true);
    let mut nd = Session::start_link_new_device(path, "new device pass", "laptop", server).expect("start");
    println!("LINK {}", nd.link());
    loop {
        let st = nd.poll().expect("poll");
        println!("STATUS {st:?}");
        if let LinkStatus::Code { .. } = st {
            std::thread::sleep(Duration::from_secs(3));
            let st = nd.confirm(answer).expect("confirm");
            println!("CONFIRMED({answer}) {st:?}");
            break;
        }
        std::thread::sleep(Duration::from_secs(3));
    }
    for _ in 0..200 {
        let st = nd.poll().expect("poll");
        println!("STATUS {st:?}");
        if matches!(st, LinkStatus::Linked { .. } | LinkStatus::Cancelled { .. }) {
            break;
        }
        std::thread::sleep(Duration::from_secs(3));
    }
}
