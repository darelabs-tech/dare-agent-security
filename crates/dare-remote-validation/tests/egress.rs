//! Egress classification at the public boundary (BLUEPRINT §4.4, §7.3).
//! Proxy variables are proven ignored in `no_proxy.rs` (its own binary,
//! because it sets process-wide environment variables).

use std::net::IpAddr;

use dare_remote_validation::address::{classify, permitted, AddressClass, NetworkScope};

fn class(ip: &str) -> AddressClass {
    classify(ip.parse::<IpAddr>().unwrap())
}

#[test]
fn the_172_16_slash_12_boundaries() {
    assert_eq!(class("172.15.255.255"), AddressClass::Public);
    assert_eq!(class("172.16.0.0"), AddressClass::Private);
    assert_eq!(class("172.31.255.255"), AddressClass::Private);
    assert_eq!(class("172.32.0.0"), AddressClass::Public);
}

#[test]
fn every_row_of_the_table() {
    for (ip, expected) in [
        ("10.0.0.1", AddressClass::Private),
        ("192.168.0.1", AddressClass::Private),
        ("127.0.0.1", AddressClass::Loopback),
        ("::1", AddressClass::Loopback),
        ("169.254.169.254", AddressClass::Metadata),
        ("fd00:ec2::254", AddressClass::Metadata),
        ("169.254.1.1", AddressClass::LinkLocal),
        ("fe80::1", AddressClass::LinkLocal),
        ("fc00::1", AddressClass::Private),
        ("0.0.0.0", AddressClass::Reserved),
        ("::", AddressClass::Reserved),
        ("224.0.0.1", AddressClass::Reserved),
        ("100.64.0.1", AddressClass::Private),
        ("::ffff:10.0.0.1", AddressClass::Private),
        ("::ffff:127.0.0.1", AddressClass::Loopback),
        ("8.8.8.8", AddressClass::Public),
        ("2001:4860:4860::8888", AddressClass::Public),
    ] {
        assert_eq!(class(ip), expected, "{ip}");
    }
}

#[test]
fn metadata_link_local_and_reserved_are_never_permitted_in_any_scope() {
    for scope in [
        NetworkScope::Public,
        NetworkScope::Private,
        NetworkScope::LoopbackLab,
    ] {
        for c in [
            AddressClass::Metadata,
            AddressClass::LinkLocal,
            AddressClass::Reserved,
        ] {
            assert!(!permitted(c, scope), "{c:?} in {scope:?}");
        }
    }
    assert!(permitted(AddressClass::Public, NetworkScope::Public));
    assert!(!permitted(AddressClass::Private, NetworkScope::Public));
    assert!(!permitted(AddressClass::Loopback, NetworkScope::Public));
}
