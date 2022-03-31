use super::proto::PcrAlgo;

pub struct Bank {
    /// PCR bank algorithm, e.g. sha1, sha256 ...
    pub algo_id: PcrAlgo,
    /// Bitmask of PCRs we are interested in.
    pub pcrs: u32,
}

/// Appraisal policy
#[derive(Copy, Clone)]
pub struct Policy {
    /// Contains list of PCR banks we are interested in. All banks are mandatory
    /// and attestation will fail if bank if missing.
    pub banks: &'static [Bank],
}

impl Default for Policy {
    fn default() -> Self {
        // TODO: policy should not be hardcoded, instead default policy should
        // be configured during provisioning of Fobnail token.
        Self {
            banks: &[Bank {
                algo_id: PcrAlgo::Sha256,
                pcrs: 0x000600ff,
            }],
        }
    }
}
