/// Appraisal policy
#[derive(Copy, Clone)]
pub struct Policy {
    // TODO: implement an actual policy
}

impl Default for Policy {
    fn default() -> Self {
        // TODO: policy should not be hardcoded, instead default policy should
        // be configured during provisioning of Fobnail token.
        Self {}
    }
}
