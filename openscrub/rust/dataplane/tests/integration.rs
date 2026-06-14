// SPDX-License-Identifier: Apache-2.0
//
// Integration tests for openscrub-dataplane.
//
// Tests under `live_kernel` require:
//   - Linux host
//   - CAP_BPF + CAP_NET_ADMIN (run with sudo)
//   - openscrub.bpf.o built (`make -C openscrub/ebpf`)
//
// They are gated behind `#[ignore]` so `cargo test` stays green on
// developer laptops. Run them with: `cargo test -- --ignored`.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use ipnet::{Ipv4Net, Ipv6Net};
use openscrub_dataplane::{Blocklist, MapWriter, RatelimitRule, Stats, StatsReader};

#[test]
fn map_writer_round_trip_v4() {
    let w = MapWriter::new_detached();
    let prefixes = [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "203.0.113.0/24",
    ];
    for p in prefixes {
        w.add_blocklist_v4(Ipv4Net::from_str(p).unwrap()).unwrap();
    }
    assert_eq!(w.snapshot().v4.len(), prefixes.len());

    for p in prefixes {
        w.remove_blocklist_v4(Ipv4Net::from_str(p).unwrap()).unwrap();
    }
    assert!(w.snapshot().v4.is_empty());
}

#[test]
fn map_writer_round_trip_v6() {
    let w = MapWriter::new_detached();
    w.add_blocklist_v6(Ipv6Net::from_str("2001:db8::/32").unwrap()).unwrap();
    w.add_blocklist_v6(Ipv6Net::from_str("fe80::/10").unwrap()).unwrap();
    assert_eq!(w.snapshot().v6.len(), 2);
}

#[test]
fn ratelimit_overwrites_existing_rule() {
    let w = MapWriter::new_detached();
    let src = Ipv4Addr::new(198, 51, 100, 7);
    w.set_ratelimit(RatelimitRule::new(src, 100).unwrap()).unwrap();
    w.set_ratelimit(RatelimitRule::new(src, 5000).unwrap()).unwrap();
    assert_eq!(w.snapshot().ratelimit.get(&src), Some(&5000));
}

#[test]
fn snapshot_is_independent_of_writer() {
    let w = MapWriter::new_detached();
    w.add_blocklist_v4(Ipv4Net::from_str("10.0.0.0/8").unwrap()).unwrap();
    let snap = w.snapshot();
    w.add_blocklist_v4(Ipv4Net::from_str("172.16.0.0/12").unwrap()).unwrap();
    // Snapshot must not see mutations after it was taken.
    assert_eq!(snap.v4.len(), 1);
    assert_eq!(w.snapshot().v4.len(), 2);
}

#[test]
fn stats_reader_default_is_zero() {
    let r = StatsReader::new_detached();
    let s = r.read().unwrap();
    assert_eq!(s, Stats::default());
    assert_eq!(s.total_seen(), 0);
}

#[test]
fn blocklist_clone_decouples_from_writer() {
    let w = MapWriter::new_detached();
    w.add_blocklist_v4(Ipv4Net::from_str("10.0.0.0/8").unwrap()).unwrap();
    let mut b: Blocklist = w.snapshot();
    b.v4.clear();
    // Clearing the snapshot must not affect the writer.
    assert_eq!(w.snapshot().v4.len(), 1);
}

// ── Live-kernel tests (require Linux + CAP_BPF) ──────────────────────

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires CAP_BPF + compiled openscrub.bpf.o"]
fn live_kernel_attach_to_loopback() {
    use openscrub_dataplane::{AttachMode, Loader};

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut loader = Loader::from_default_path();
        loader
            .attach("lo", AttachMode::Skb)
            .await
            .expect("attach to lo failed — run as root with openscrub.bpf.o built");
        let w = loader.map_writer();
        w.add_blocklist_v4(Ipv4Net::from_str("203.0.113.0/24").unwrap())
            .unwrap();
        loader.detach().await.unwrap();
    });
}
