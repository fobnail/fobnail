use alloc::{rc::Rc, vec::Vec};
use core::fmt;

use crate::certmgr::X509Certificate;

use super::crypto::Key;

pub enum State<'a> {
    /// Send request to obtain EK certificate
    RequestEkCertChain { request_pending: bool },

    /// Verify EK certificate chain
    VerifyEkCertificateChain { data: Vec<u8> },

    RequestAik {
        // FIXME:
        // This field is wrapped in option to allow moving inner value into next
        // state. This is a hack we are using because Rust won't allow us to
        // move object. Should work on improving state machine patterns so that
        // we can update state atomically or get replace state machine with some
        // other approach.
        ek_cert: Option<X509Certificate<'static>>,
        request_pending: bool,
    },

    /// Do basic parsing and verification of received AIK. Prepare challenge
    /// that attester has to pass (credential activation) to confirm that AIK
    /// comes from TPM (AIK is bound to EK).
    VerifyAikStage1 {
        ek_cert: X509Certificate<'static>,
        data: Vec<u8>,
    },

    /// Send AIK challenge. Attester decrypts secret which is part of challenge
    /// and returns secret as plaintext. If decrypted secret matches with secret
    /// stored in memory then verification succeeds.
    VerifyAikStage2 {
        request_pending: bool,
        secret: Vec<u8>,
        id_object: Vec<u8>,
        encrypted_secret: Vec<u8>,
        aik: Vec<u8>,
    },

    /// Parse and load AIK key.
    LoadAik { raw_aik: Vec<u8> },

    /// Send metadata request and wait for response.
    RequestMetadata {
        aik_pubkey: Rc<Key<'a>>,
        request_pending: bool,
    },

    /// Verify whether metadata has been properly signed with the Attestation
    /// Identity Key.
    VerifyMetadata {
        aik_pubkey: Rc<Key<'a>>,
        metadata: Vec<u8>,
    },

    /// Request Reference Integrity Manifests from attester.
    RequestRim {
        /// RIMs are bound to a specific device. We use metadata hashes to
        /// distinguish these devices.
        metadata_hash: Vec<u8>,
        aik_pubkey: Rc<Key<'a>>,
        request_pending: bool,
    },

    /// Verify Reference Integrity Manifest, store it together with public part
    /// of AIK.
    VerifyStoreRimAik {
        metadata_hash: Vec<u8>,
        rim: Vec<u8>,
        aik_pubkey: Rc<Key<'a>>,
    },

    /// Idle state with optional timeout. After timeout resets into Init state.
    Idle { timeout: Option<u64> },

    /// Triggered on error, blinks red LED to signal that provisioning has
    /// failed.
    SignalStatus {
        n_blinks_plus_1: u32,
        led_on: bool,
        timeout: u64,
        blink_period: u32,
        success: bool,
    },

    /// Provisioning is complete.
    Done,
}

impl State<'_> {
    /// Transition into error state.
    pub fn error(&mut self) {
        // Quickly blink 3 times
        *self = Self::SignalStatus {
            n_blinks_plus_1: 4,
            led_on: false,
            timeout: 0,
            blink_period: 100,
            success: false,
        }
    }

    /// Signal success using green, then transition into complete state. In this
    /// state client becomes permanently idle.
    pub fn done(&mut self) {
        // Quickly blink with green LED to signal that provisioning is
        // successful.
        *self = Self::SignalStatus {
            n_blinks_plus_1: 4,
            led_on: false,
            timeout: 0,
            blink_period: 100,
            success: true,
        }
    }
}

impl Default for State<'_> {
    fn default() -> Self {
        Self::RequestEkCertChain {
            request_pending: false,
        }
    }
}

impl fmt::Display for State<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequestEkCertChain { .. } => write!(f, "request EK certificate chain"),
            Self::VerifyEkCertificateChain { .. } => write!(f, "verify EK certificate chain"),
            Self::RequestAik { .. } => write!(f, "request AIK"),
            Self::VerifyAikStage1 { .. } => write!(f, "verify AIK (stage 1)"),
            Self::VerifyAikStage2 { .. } => write!(f, "verify AIK (stage 2)"),
            Self::LoadAik { .. } => write!(f, "load AIK"),
            Self::RequestMetadata { .. } => write!(f, "request metadata"),
            Self::VerifyMetadata { .. } => write!(f, "verify metadata"),
            Self::RequestRim { .. } => write!(f, "request RIM"),
            Self::VerifyStoreRimAik { .. } => write!(f, "verify RIM"),
            Self::Idle { .. } => write!(f, "idle"),
            Self::SignalStatus { .. } => write!(f, "signal status"),
            Self::Done => write!(f, "done"),
        }
    }
}
