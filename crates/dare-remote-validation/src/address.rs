//! Address classification (BLUEPRINT §4.4).
//!
//! The SSRF control. Every address a hostname resolves to, and every IP
//! literal in an origin, is classified here before a socket is opened. Order
//! matters: cloud metadata addresses sit inside link-local space and are
//! checked first so they get their own class; an IPv4-mapped IPv6 address is
//! classified as the IPv4 address it embeds.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AddressClass {
    Public,
    Private,
    Loopback,
    LinkLocal,
    Metadata,
    Reserved,
}

/// Which non-public classes an authorization opened.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NetworkScope {
    #[default]
    Public,
    Private,
    LoopbackLab,
}

fn in_v4(ip: Ipv4Addr, net: [u8; 4], prefix: u32) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (u32::from(ip) & mask) == (u32::from(Ipv4Addr::from(net)) & mask)
}

fn in_v6(ip: Ipv6Addr, net: Ipv6Addr, prefix: u32) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    (u128::from(ip) & mask) == (u128::from(net) & mask)
}

fn classify_v4(ip: Ipv4Addr) -> AddressClass {
    const METADATA: [([u8; 4], u32); 2] = [([169, 254, 169, 254], 32), ([169, 254, 170, 2], 32)];
    const LOOPBACK: [([u8; 4], u32); 1] = [([127, 0, 0, 0], 8)];
    const PRIVATE: [([u8; 4], u32); 4] = [
        ([10, 0, 0, 0], 8),
        ([172, 16, 0, 0], 12),
        ([192, 168, 0, 0], 16),
        ([100, 64, 0, 0], 10),
    ];
    const LINK_LOCAL: [([u8; 4], u32); 1] = [([169, 254, 0, 0], 16)];
    const RESERVED: [([u8; 4], u32); 9] = [
        ([0, 0, 0, 0], 8),
        ([192, 0, 0, 0], 24),
        ([192, 0, 2, 0], 24),
        ([198, 18, 0, 0], 15),
        ([198, 51, 100, 0], 24),
        ([203, 0, 113, 0], 24),
        ([224, 0, 0, 0], 4),
        ([240, 0, 0, 0], 4),
        ([255, 255, 255, 255], 32),
    ];
    let any = |table: &[([u8; 4], u32)]| table.iter().any(|(net, p)| in_v4(ip, *net, *p));
    if any(&METADATA) {
        AddressClass::Metadata
    } else if any(&LOOPBACK) {
        AddressClass::Loopback
    } else if any(&PRIVATE) {
        AddressClass::Private
    } else if any(&LINK_LOCAL) {
        AddressClass::LinkLocal
    } else if any(&RESERVED) {
        AddressClass::Reserved
    } else {
        AddressClass::Public
    }
}

fn classify_v6(ip: Ipv6Addr) -> AddressClass {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return classify_v4(v4);
    }
    let metadata = Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254);
    let table: [(Ipv6Addr, u32, AddressClass); 10] = [
        (metadata, 128, AddressClass::Metadata),
        (Ipv6Addr::LOCALHOST, 128, AddressClass::Loopback),
        (
            Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0),
            7,
            AddressClass::Private,
        ),
        (
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0),
            10,
            AddressClass::LinkLocal,
        ),
        (Ipv6Addr::UNSPECIFIED, 128, AddressClass::Reserved),
        (
            Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0, 0),
            96,
            AddressClass::Reserved,
        ),
        (
            Ipv6Addr::new(0x0100, 0, 0, 0, 0, 0, 0, 0),
            64,
            AddressClass::Reserved,
        ),
        (
            Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0),
            32,
            AddressClass::Reserved,
        ),
        (
            Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0),
            8,
            AddressClass::Reserved,
        ),
        // IPv4-compatible (deprecated) addresses embed an IPv4 address too.
        (Ipv6Addr::UNSPECIFIED, 96, AddressClass::Reserved),
    ];
    for (net, prefix, class) in table {
        if in_v6(ip, net, prefix) {
            return class;
        }
    }
    AddressClass::Public
}

/// Classify one address.
pub fn classify(ip: IpAddr) -> AddressClass {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

/// Whether a class may be contacted under a scope.
pub fn permitted(class: AddressClass, scope: NetworkScope) -> bool {
    match class {
        AddressClass::Public => true,
        AddressClass::Private => scope == NetworkScope::Private,
        AddressClass::Loopback => scope == NetworkScope::LoopbackLab,
        AddressClass::Metadata | AddressClass::LinkLocal | AddressClass::Reserved => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use AddressClass::*;

    fn c(s: &str) -> AddressClass {
        classify(s.parse().expect(s))
    }

    #[test]
    fn the_blueprint_table_row_by_row() {
        for (ip, class) in [
            ("169.254.169.254", Metadata),
            ("169.254.170.2", Metadata),
            ("fd00:ec2::254", Metadata),
            ("127.0.0.1", Loopback),
            ("127.255.255.254", Loopback),
            ("::1", Loopback),
            ("10.1.2.3", Private),
            ("172.16.0.1", Private),
            ("192.168.1.1", Private),
            ("100.64.0.1", Private),
            ("fc00::1", Private),
            ("fd12:3456::1", Private),
            ("169.254.1.1", LinkLocal),
            ("fe80::1", LinkLocal),
            ("0.0.0.0", Reserved),
            ("0.1.2.3", Reserved),
            ("192.0.0.8", Reserved),
            ("192.0.2.1", Reserved),
            ("198.18.0.1", Reserved),
            ("198.19.255.255", Reserved),
            ("198.51.100.7", Reserved),
            ("203.0.113.9", Reserved),
            ("224.0.0.1", Reserved),
            ("239.255.255.255", Reserved),
            ("240.0.0.1", Reserved),
            ("255.255.255.255", Reserved),
            ("::", Reserved),
            ("64:ff9b::a00:1", Reserved),
            ("100::1", Reserved),
            ("2001:db8::1", Reserved),
            ("ff02::1", Reserved),
            ("8.8.8.8", Public),
            ("1.1.1.1", Public),
            ("2606:4700::1111", Public),
        ] {
            assert_eq!(c(ip), class, "{ip}");
        }
    }

    #[test]
    fn range_boundaries() {
        assert_eq!(c("172.15.255.255"), Public);
        assert_eq!(c("172.16.0.0"), Private);
        assert_eq!(c("172.31.255.255"), Private);
        assert_eq!(c("172.32.0.0"), Public);
        assert_eq!(c("100.63.255.255"), Public);
        assert_eq!(c("100.127.255.255"), Private);
        assert_eq!(c("100.128.0.0"), Public);
        assert_eq!(c("9.255.255.255"), Public);
        assert_eq!(c("11.0.0.0"), Public);
        assert_eq!(c("223.255.255.255"), Public);
        assert_eq!(c("fbff:ffff::1"), Public);
        assert_eq!(c("fec0::1"), Public);
    }

    #[test]
    fn ipv4_mapped_and_compatible_addresses_cannot_hide_a_private_one() {
        assert_eq!(c("::ffff:127.0.0.1"), Loopback);
        assert_eq!(c("::ffff:169.254.169.254"), Metadata);
        assert_eq!(c("::ffff:10.0.0.1"), Private);
        assert_eq!(c("::ffff:8.8.8.8"), Public);
        assert_eq!(c("::127.0.0.1"), Reserved);
    }

    #[test]
    fn permission_by_scope() {
        use NetworkScope as S;
        for scope in [S::Public, S::Private, S::LoopbackLab] {
            assert!(permitted(Public, scope));
            for never in [Metadata, LinkLocal, Reserved] {
                assert!(!permitted(never, scope), "{never:?} under {scope:?}");
            }
        }
        assert!(permitted(Private, S::Private));
        assert!(!permitted(Private, S::Public));
        assert!(!permitted(Private, S::LoopbackLab));
        assert!(permitted(Loopback, S::LoopbackLab));
        assert!(!permitted(Loopback, S::Public));
        assert!(!permitted(Loopback, S::Private));
    }
}
