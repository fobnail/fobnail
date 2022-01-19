pub struct MacAddress(pub [u8; 6]);

pub struct Metadata {}

impl Metadata {
    pub fn deserialize(buf: &[u8]) -> Self {
        todo!()
    }

    pub fn mac_address(&self) -> MacAddress {
        todo!()
    }

    pub fn serial_number(&self) -> &[u8] {
        todo!()
    }

    pub fn ek_hash(&self) -> &[u8] {
        todo!()
    }
}
