use smoltcp::phy::TapInterface;
use smoltcp::wire::EthernetAddress;

/// Creates Ethernet PHY which we use with smoltcp
pub fn create_phy() -> TapInterface {
    TapInterface::new("fobnail0").unwrap()
}

/// Returns MAC address which should be used when building interface using
/// `EthernetInterfaceBuilder`
pub fn get_ethernet_address() -> EthernetAddress {
    EthernetAddress([0x10, 0x20, 0x30, 0x40, 0x50, 0x60])
}
