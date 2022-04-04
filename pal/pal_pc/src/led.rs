#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Led {
    Green,
    Red,
}

pub fn control(_led: Led, _on: bool) {
    // since on PC there is no LED we could control this is no-op kept only to
    // uniform PAL interface between pal_nrf and pal_pc
}
