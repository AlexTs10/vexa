//! The address rule of the outbound-URL guard (ssrf.py's is_blocked_ip), for
//! the addresses a custom service's host resolves to: every address is checked
//! as what it reaches, including the IPv4 address an IPv6 form carries.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const V4: [(u32, u8); 15] = [
    (0x0000_0000, 8),
    (0x0a00_0000, 8),
    (0x6440_0000, 10),
    (0x7f00_0000, 8),
    (0xa9fe_0000, 16),
    (0xac10_0000, 12),
    (0xc000_0000, 24),
    (0xc000_0200, 24),
    (0xc058_6300, 24),
    (0xc0a8_0000, 16),
    (0xc612_0000, 15),
    (0xc633_6400, 24),
    (0xcb00_7100, 24),
    (0xe000_0000, 4),
    (0xf000_0000, 4),
];

const V6: [(u128, u8); 12] = [
    (0, 128),
    (1, 128),
    (0x0064_ff9b_0001 << 80, 48),
    (0x0100 << 112, 64),
    (0x2001 << 112, 23),
    (0x2001_0db8 << 96, 32),
    (0x3fff << 112, 20),
    (0x5f00 << 112, 16),
    (0xfc00 << 112, 7),
    (0xfe80 << 112, 10),
    (0xfec0 << 112, 10),
    (0xff00 << 112, 8),
];

fn in4(ip: u32, (net, len): (u32, u8)) -> bool {
    len == 0 || (ip >> (32 - len as u32)) == (net >> (32 - len as u32))
}

fn in6(ip: u128, net: u128, len: u8) -> bool {
    len == 0 || (ip >> (128 - len as u32)) == (net >> (128 - len as u32))
}

/// Every IPv4 address an IPv6 address carries.
fn embedded(ip: &Ipv6Addr) -> Vec<Ipv4Addr> {
    let n = u128::from(*ip);
    let low32 = Ipv4Addr::from(n as u32);
    let mut out = Vec::new();
    // IPv4-mapped, IPv4-translated, or IPv4-compatible (not :: and not ::1).
    if in6(n, 0xffff << 32, 96) || in6(n, 0xffff << 48, 96) || (in6(n, 0, 96) && n > 1) {
        out.push(low32);
    }
    if in6(n, 0x0064_ff9b << 96, 96) {
        out.push(low32);
    }
    if in6(n, 0x2002 << 112, 16) {
        out.push(Ipv4Addr::from((n >> 80) as u32));
    }
    if in6(n, 0x2001_0000 << 96, 32) {
        out.push(Ipv4Addr::from((n >> 64) as u32));
        out.push(Ipv4Addr::from(!(n as u32)));
    }
    if [0x0000_5efe, 0x0100_5efe, 0x0200_5efe, 0x0300_5efe].contains(&((n >> 32) as u32)) {
        out.push(low32);
    }
    out
}

pub fn is_blocked_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => V4.iter().any(|&net| in4(u32::from(*v4), net)),
        IpAddr::V6(v6) => {
            let carried = embedded(v6);
            if carried.iter().any(|v4| is_blocked_ip(&IpAddr::V4(*v4))) {
                return true;
            }
            let n = u128::from(*v6);
            if V6.iter().any(|&(net, len)| in6(n, net, len)) {
                return true;
            }
            in6(n, 0, 8) && carried.is_empty()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blocked(s: &str) -> bool {
        is_blocked_ip(&s.parse().unwrap())
    }

    #[test]
    fn refuses_internal_addresses_in_every_form() {
        for s in ["127.0.0.1", "10.1.2.3", "169.254.169.254", "100.64.0.1", "192.168.1.1", "0.0.0.0", "255.255.255.255", "::1", "::", "fd00:ec2::254", "fe80::1", "::ffff:127.0.0.1", "::ffff:0:10.0.0.1", "64:ff9b::a00:1", "2002:7f00:1::", "::5efe:a00:1", "::127.0.0.1"] {
            assert!(blocked(s), "{s}");
        }
        for s in ["8.8.8.8", "142.250.1.1", "2607:f8b0::1", "::ffff:8.8.8.8", "64:ff9b::808:808"] {
            assert!(!blocked(s), "{s}");
        }
    }
}
