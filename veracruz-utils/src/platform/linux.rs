//! Structs needed for Linux support, both inside and outside of the
//! trusted application.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use serde::{Deserialize, Serialize};

////////////////////////////////////////////////////////////////////////////////
// Linux root enclave messages.
////////////////////////////////////////////////////////////////////////////////

/// Incoming messages to the Linux root enclave, instructing it to perform some
/// act.  These are sent serialized in `bincode` format.
#[derive(Clone, Debug, Deserialize, Eq, Serialize, PartialEq, PartialOrd, Ord)]
pub enum LinuxRootEnclaveMessage {
    /// A request to get the firmware version of the software executing inside
    /// the enclave.
    GetFirmwareVersion,
    /// A request to perform a native attestation of the runtime enclave.
    /// Note that we use PSA attestation for this step, but the attestation is
    /// "fake", offering no real value other than for demonstrative purposes.
    GetNativeAttestation,
    /// A request to perform a proxy attestation of the runtime enclave.
    /// Note that we use PSA attestation, again, for this step, but the
    /// attestation is "fake", offering no real value other than for
    /// demonstrative purposes.
    /// The fields of the message are (in order):
    /// - A certificate signing request (CSR),
    /// - A challenge ID.
    GetProxyAttestation(Vec<u8>, i32),
    /// A request to shutdown the root enclave and any enclaves that it has
    /// launched.
    Shutdown,
    /// A request to spawn a new enclave containing an instance of Veracruz.
    SpawnNewApplicationEnclave,
    /// A request to generate a challenge and a fresh challenge ID, as part of
    /// the proxy attestation process.
    StartProxyAttestation,
}

/// Responses produced by the Linux root enclave after receiving and processing
/// a `LinuxRootEnclaveMessage` element, above.
#[derive(Clone, Debug, Deserialize, Eq, Serialize, PartialEq, PartialOrd, Ord)]
pub enum LinuxRootEnclaveResponse {
    /// The firmware version of the software executing inside the runtime
    /// enclave.  For Linux, this is mocked up.
    FirmwareVersion(String),
    /// The token produced by the native attestation process is now registered
    /// with the Proxy Attestation Service.
    NativeAttestationTokenRegistered,
    /// Returns a certificate chain in response to a proxy attestation request.
    /// Fields are, in order:
    /// - An encoding of the compute enclave certificate,
    /// - An encoding of the root enclave certificate,
    /// - An encoding of the root certificate.
    CertificateChain(Vec<u8>, Vec<u8>, Vec<u8>),
    /// Success message upon installation of the certificate chain.
    CertificateChainInstalled,
    /// Acknowledgment that the root enclave is to shutdown.
    ShuttingDown,
    /// Indicates that a new Runtime Manager enclave has been spawned and this
    /// new enclave should be contacted on `localhost` using the designated
    /// port.
    EnclaveSpawned(u32),
    /// Reply with the content and the index of the freshly-generated challenge
    /// value produced as a result of the proxy attestation process starting.
    ChallengeGenerated(Vec<u8>, i32),
}
