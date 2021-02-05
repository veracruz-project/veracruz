//! Common code for implementing Veracruz host-calls
//!
//! ## About
//!
//! The Veracruz H-call interface consists of the following functions:
//! - `__veracruz_hcall_input_count()` which returns the count of secret
//!   data sources available to the program,
//! - `__veracruz_hcall_read_input()` which fills a WASM buffer with a
//!   particular input,
//! - `__veracruz_hcall_input_size()` which returns the size, in bytes, of a
//!   particular input,
//! - `__veracruz_hcall_write_output()` which can be used by the WASM
//!   program to register its result by pointing the host to a WASM buffer
//!   which is then copied into the host,
//! - `__veracruz_hcall_getrandom()` which fills a WASM buffer with random
//!   bytes taken from a platform-specific entropy source.
//!
//! The implementation of some of these functions relies on execution-engine
//! specific details, so they are mostly implemented in the engine-specific
//! files in this directory.  This file contains material common to all
//! implementations.
//!
//! Also defined in this file is the Veracruz state machine state.  The Veracruz
//! host progresses through a particular series of states during provisioning
//! to ensure that Veracruz is secure, and also that it acts a little like a
//! function which can be partially-applied.
//!
//! Finally, the Veracruz host state is also defined in this file.  This keeps
//! track of the state of the host as material is provisioned into the Veracruz
//! enclave, and is used by the host to implement some (actually, most) of the
//! H-calls mentioned above.  In particular, the host state keeps track of:
//! - The number of expected data sources that the host is expecting,
//!   derived from the policy,
//! - The number of expected data sources already provisioned, and various
//!   bits of metadata about them (e.g. who provisioned them),
//! - The current machine state, e.g. `MachineState::ReadyToExecute`,
//! - Any result that the WASM program executing on Veracruz may have
//!   written to the host with the `__veracruz_hcall_write_output()` H-call.
//!   Note that this is stored as an uninterpreted set of bytes in the host,
//!   the host doesn't necessarily know how to interpret it: that's a detail
//!   to be agreed between the participants in the computation,
//! - Some WASM engine specific details, including a reference to the WASM
//!   module executing and the linear memory of the module.  As these types
//!   are engine-specific, we abstract over them with type-variables here.
//!
//! We also include a lot of generic material for working with the host state,
//! including functions for changing various values, and bumping the host state
//! around the state machine.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Copyright
//!
//! See the file `LICENSE.markdown` in the Veracruz root directory for licensing
//! and copyright information.

use crate::error::common::VeracruzError;
use err_derive::Error;
use serde::{Deserialize, Serialize};
use std::{
    borrow::Borrow,
    cmp::Ord,
    collections::{HashMap,HashSet},
    convert::TryFrom,
    fmt::{Display, Error, Formatter},
    string::{String, ToString},
    vec::Vec,
};
use veracruz_utils::{VeracruzCapabilityIndex, VeracruzCapability, VeracruzCapabilityTable};

////////////////////////////////////////////////////////////////////////////////
// Utility functions that don't fit elsewhere.
////////////////////////////////////////////////////////////////////////////////

/// Computes a SHA-256 digest of the bytes passed to it in `buffer`.
///
/// TODO: complete this.
pub(crate) fn sha_256_digest(buffer: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, buffer)
        .as_ref()
        .to_vec()
}

////////////////////////////////////////////////////////////////////////////////
// Metadata for data sources.
////////////////////////////////////////////////////////////////////////////////

/// A data source "frame" containing the data provisioned into the enclave, as
/// well as some identifying metadata explaining where it came from.
#[derive(Clone, Debug)]
pub struct DataSourceMetadata {
    /// The raw data (encoded in bytes) provisioned into the enclave.
    data: Vec<u8>,
    /// Who provisioned this data.
    client_id: u64,
    /// The "serial number" for data issued by a single provisioner of data.
    package_id: u64,
}

impl DataSourceMetadata {
    /// Creates a new `DataSourceMetadata` frame from a source of raw bytes, and
    /// client and package IDs.
    #[inline]
    pub fn new(data: &[u8], client_id: u64, package_id: u64) -> Self {
        DataSourceMetadata {
            data: data.to_vec(),
            client_id: client_id,
            package_id: package_id,
        }
    }

    /// Gets the raw bytes associated with this metadata frame.
    #[inline]
    pub fn get_data(&self) -> &Vec<u8> {
        &self.data
    }

    /// Gets the client ID associated with this metadata frame.
    #[inline]
    pub fn get_client_id(&self) -> u64 {
        self.client_id
    }

    /// Gets the package ID associated with this metadata frame.
    #[inline]
    pub fn get_package_id(&self) -> u64 {
        self.package_id
    }
}

/// Pretty-printing for `DataSourceMetadata`.
impl Display for DataSourceMetadata {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(
            f,
            "Data source (client ID: {}, package ID: {}) bytes:\n",
            self.client_id, self.package_id
        )?;
        write!(f, "  {:?}", self.data)
    }
}

////////////////////////////////////////////////////////////////////////////////
// The machine lifecycle state.
////////////////////////////////////////////////////////////////////////////////

/// The lifecycle state of the Veracruz host.
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum LifecycleState {
    /// The initial state: nothing yet has been provisioned into the Veracruz
    /// machine.  The state is essentially "pristine", having just been created.
    Initial,
    /// The program has been provisioned into the machine, and now the data
    /// sources are in the process of being provisioned.  Not all data sources
    /// are yet provisioned, per the global policy.
    DataSourcesLoading,
    /// The program and (initial) data have been provisioned into the machine,
    /// and now the stream sources are in the process of being provisioned.
    /// Not all stream sources are yet provisioned, per the global policy.
    StreamSourcesLoading,
    /// All data and stream sources (and the program) have now been provisioned according
    /// to the global policy.  The machine is now ready to execute.
    ReadyToExecute,
    /// The machine has executed, and finished successfully.  The result of the
    /// machine's execution can now be extracted.
    FinishedExecuting,
    /// An error occurred during the provisioning or machine execution process.
    Error,
}

/// Pretty printing for `LifecycleState`.
impl Display for LifecycleState {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        match self {
            LifecycleState::Initial => write!(f, "Initial"),
            LifecycleState::DataSourcesLoading => write!(f, "DataSourcesLoading"),
            LifecycleState::StreamSourcesLoading => write!(f, "StreamSourcesLoading"),
            LifecycleState::ReadyToExecute => write!(f, "ReadyToExecute"),
            LifecycleState::FinishedExecuting => write!(f, "FinishedExecuting"),
            LifecycleState::Error => write!(f, "Error"),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// The H-Call API
////////////////////////////////////////////////////////////////////////////////

/// Name of the `__veracruz_hcall_input_count` H-call.
pub(crate) const HCALL_INPUT_COUNT_NAME: &'static str = "__veracruz_hcall_input_count";
/// Name of the `__veracruz_hcall_input_size` H-call.
pub(crate) const HCALL_INPUT_SIZE_NAME: &'static str = "__veracruz_hcall_input_size";
/// Name of the `__veracruz_hcall_read_input` H-call.
pub(crate) const HCALL_READ_INPUT_NAME: &'static str = "__veracruz_hcall_read_input";
/// Name of the `__veracruz_hcall_write_output` H-call.
pub(crate) const HCALL_WRITE_OUTPUT_NAME: &'static str = "__veracruz_hcall_write_output";
/// Name of the `__veracruz_hcall_getrandom` H-call.
pub(crate) const HCALL_GETRANDOM_NAME: &'static str = "__veracruz_hcall_getrandom";
/// Name of the `__veracruz_hcall_read_previous_result` H-call.
pub(crate) const HCALL_READ_PREVIOUS_RESULT_NAME: &str = "__veracruz_hcall_read_previous_result";
/// Name of the `__veracruz_hcall_previous_result_size` H-call.
pub(crate) const HCALL_PREVIOUS_RESULT_SIZE_NAME: &str = "__veracruz_hcall_previous_result_size";
/// Name of the `__veracruz_hcall_has_previous_result` H-call.
pub(crate) const HCALL_HAS_PREVIOUS_RESULT_NAME: &str = "__veracruz_hcall_has_previous_result";
/// H-call code for the `__veracruz_hcall_stream_count` H-call.
pub(crate) const HCALL_STREAM_COUNT_NAME: &str = "__veracruz_hcall_stream_count";
/// H-call code for the `__veracruz_hcall_stream_size` H-call.
pub(crate) const HCALL_STREAM_SIZE_NAME: &str = "__veracruz_hcall_stream_size";
/// H-call code for the `__veracruz_hcall_read_stream` H-call.
pub(crate) const HCALL_READ_STREAM_NAME: &str = "__veracruz_hcall_read_stream";

////////////////////////////////////////////////////////////////////////////////
// Provisioning errors
////////////////////////////////////////////////////////////////////////////////

/// Errors that can occur during host provisioning.  These are errors that may
/// be reported back to principals in the Veracruz computation over the Veracruz
/// wire protocols, for example if somebody tries to provision data when that is
/// not expected, or similar.  Some may be recoverable errors, some may be fatal
/// errors due to programming bugs.
#[derive(Debug, Error)]
pub enum HostProvisioningError {
    /// The provisioning process failed because it could not correctly sort the
    /// incoming data.  This should never happen, and is a bug.
    #[error(
        display = "HostProvisioningError: Failed to sort incoming data (this is a potential bug)."
    )]
    FailedToSortIncomingData,
    /// The host state was in an unexpected, or invalid, lifecycle state and
    /// there is a mismatch between actual provisioning state and what was
    /// expected.
    #[error(
        display = "HostProvisioningError: Invalid host state, found {:?}, expected {:?}.",
        found,
        expected
    )]
    InvalidLifeCycleState {
        found: LifecycleState,
        expected: Vec<LifecycleState>,
    },
    /// The WASM module supplied by the program supplier was invalid and could
    /// not be parsed.
    #[error(display = "HostProvisioningError: Invalid WASM program (e.g. failed to parse it).")]
    InvalidWASMModule,
    /// No linear memory/heap could be identified in the WASM module.
    #[error(
        display = "HostProvisioningError: No linear memory could be found in the supplied WASM module."
    )]
    NoLinearMemoryFound,
    /// The program module could not be properly instantiated by the WASM engine
    /// for some reason.
    #[error(display = "HostProvisioningError: Failed to instantiate the WASM module.")]
    ModuleInstantiationFailure,
    /// A lock could not be obtained for some reason.
    #[error(display = "HostProvisioningError: Failed to obtain lock {:?}.", _0)]
    FailedToObtainLock(String),
    /// The host provisioning state has not been initialized.  This should never
    /// happen and is a bug.
    #[error(
        display = "HostProvisioningError: Uninitialized host provisioning state (this is a potential bug)."
    )]
    HostProvisioningStateNotInitialized,
    /// The data or stream data cannot be sorted. This should never happen and is a bug.
    #[error(
        display = "HostProvisioningError: Failed to sort the incoming data or incoming stream (this is a potential bug)."
    )]
    CannotSortDataOrStream,
    //TODO: potential remove this 
    #[error(
        display = "HostProvisioningError: File {} cannot be found.", _0
    )]
    FileNotFound(String),
    #[error(
        display = "HostProvisioningError: Principal or program {:?} cannot be found.",_0
    )]
    IndexNotFound(VeracruzCapabilityIndex),
    #[error(
        display = "HostProvisioningError: Client {:?} is disallowed to {:?}.",client_id,operation
    )]
    CapabilityDenial {
        client_id: VeracruzCapabilityIndex,
        operation : VeracruzCapability,
    },
}

// Convertion from any error raised by any mutex of type <T> to HostProvisioningError.
impl<T> From<std::sync::PoisonError<T>> for HostProvisioningError {
    fn from(error: std::sync::PoisonError<T>) -> Self {
        HostProvisioningError::FailedToObtainLock(format!("{:?}", error))
    }
}

////////////////////////////////////////////////////////////////////////////////
// The Veracruz provisioning state.
////////////////////////////////////////////////////////////////////////////////

/// The state of the Veracruz machine, which captures metadata as the Veracruz
/// state is gradually "provisioned" by the data and program providers.  Also
/// contains enough data to properly implement the Veracruz H-calls.
#[derive(Clone)]
// TODO: remove MOST, except:
// - memory
// - program_module ? possibly can do on-demand allocation
// in the favour of FS.
pub struct HostProvisioningState<Module, Memory> {
    /// The data sources that have been provisioned into the machine.
    data_sources: Vec<DataSourceMetadata>,
    /// The stream sources that have been provisioned into the machine.
    stream_sources: Vec<DataSourceMetadata>,
    /// The expected list of data sources, derived from the global policy
    /// parameterising the computation.
    expected_data_sources: Vec<u64>,
    /// The expected list of stream sources, derived from the global policy
    /// parameterising the computation.
    expected_stream_sources: Vec<u64>,
    /// The current lifecycle state of the machine.
    lifecycle_state: LifecycleState,
    /// A reference to the WASM program module that will actually execute on
    /// the input data sources.
    program_module: Option<Module>,
    /// The SHA-256 digest of the bytes of the loaded program, if any.
    program_digest: Option<Vec<u8>>,
    /// A reference to the WASM program's linear memory (or "heap").
    memory: Option<Memory>,
    /// The result of the previous execution.
    previous_result: Option<Vec<u8>>,
    /// The result of the WASM program's computation on the input sources above.
    result: Option<Vec<u8>>,
    /// The list of clients (their IDs) that can request shutdown of the
    /// Veracruz platform.
    expected_shutdown_sources: Vec<u64>,
    //NOTE: the following will move to an external component.
    //TODO: integrate into FS
    //      Index -> FilePath -> Capability
    capabilities: VeracruzCapabilityTable,
    //      Program_file_name -> Digest
    program_digests: HashMap<String, Vec<u8>>, 
}

impl<Module, Memory> HostProvisioningState<Module, Memory> {
    ////////////////////////////////////////////////////////////////////////////
    // Creating and modifying host states.
    ////////////////////////////////////////////////////////////////////////////

    /// Creates a new initial `HostProvisioningState`.
    //TODO: Deprecated semi-valid HostProvisioningState.
    //      Pass:
    //      - file permission, which controls and replace, stream_sources, data_sources, program_digest, previous_result, result, expected_data_sources, expected_stream_sources
    //      - expected_shutdown_sources
    #[inline]
    pub fn new() -> Self {
        HostProvisioningState {
            data_sources: Vec::new(),
            expected_data_sources: Vec::new(),
            stream_sources: Vec::new(),
            expected_stream_sources: Vec::new(),
            lifecycle_state: LifecycleState::Initial,
            program_module: None,
            program_digest: None,
            memory: None,
            previous_result: None,
            result: None,
            expected_shutdown_sources: Vec::new(),
            capabilities: HashMap::new(),
            program_digests: HashMap::new(),
        }
    }

    //TODO: THIS will replace the use of `new` in the future commits.
    pub fn valid_new(expected_shutdown_sources: &[u64], 
        capabilities: &VeracruzCapabilityTable,
        program_digests: &HashMap<String, Vec<u8>>, 
    ) -> Self {
        let mut capabilities = capabilities.clone();
        HostProvisioningState {
            data_sources: Vec::new(),
            expected_data_sources: Vec::new(),
            stream_sources: Vec::new(),
            expected_stream_sources: Vec::new(),
            lifecycle_state: LifecycleState::Initial,
            program_module: None,
            program_digest: None,
            memory: None,
            previous_result: None,
            result: None,
            expected_shutdown_sources : expected_shutdown_sources.to_vec(),
            //capabilities: capabilities.clone(),
            capabilities,
            program_digests: program_digests.clone(),
        }
    }

    // NOTE: the following will move to an external component.
    /// Return Some(CapabilityFlags) if `id` has the permission 
    /// to read, write and execute on the `file_name`.
    /// Return None if `id` or `file_name` do not exist.
    pub(crate) fn check_capability(&self, id: &VeracruzCapabilityIndex, file_name: &str, cap: &VeracruzCapability) -> Result<(), HostProvisioningError> {
        self.capabilities
            .get(&VeracruzCapabilityIndex::Principal(0))
            .ok_or(HostProvisioningError::IndexNotFound(id.clone()))?
            .get(file_name)
            .ok_or(HostProvisioningError::FileNotFound(file_name.to_string()))
            .and_then(|p| {
                if p.contains(cap) {
                    Ok(())
                } else {
                    Err(HostProvisioningError::CapabilityDenial{
                        client_id: id.clone(),
                        operation: cap.clone(),
                    })
                }
            })
    }

    /// Append to a file.
    pub(crate) fn append_file(&mut self, client_id: u64, file_name: &str, data: &[u8]) -> Result<(), HostProvisioningError> {
        self.check_capability(&VeracruzCapabilityIndex::Principal(client_id),file_name, &VeracruzCapability::Write)?;
        //TODO: link to the actually fs API.
        //TODO: THIS ONLY IS GLUE CODE FOR NOW!
        if file_name.starts_with("input-") {
            let package_id = file_name.strip_prefix("input-").unwrap().parse::<u64>().unwrap();
            let metadata = DataSourceMetadata::new(
                data,
                client_id,
                package_id,
            );
            self.add_new_data_source(metadata)
        } else if file_name.starts_with("stream-") {
            let package_id = file_name.strip_prefix("stream-").unwrap().parse::<u64>().unwrap();
            let metadata = DataSourceMetadata::new(
                data,
                client_id,
                package_id,
            );
            self.add_new_stream_source(metadata)
        } else {
            Err(HostProvisioningError::FileNotFound(file_name.to_string()))
        }
    }

    /// Read from a file
    pub(crate) fn read_file(&self, client_id: u64, file_name: &str) -> Result<Option<Vec<u8>>, HostProvisioningError> {
        //TODO: link to the actually fs API.
        //TODO: THIS ONLY IS GLUE CODE FOR NOW!
        if file_name.starts_with("output") {
            Ok(self.get_result().map(|v| v.to_vec()))
        } else {
            Err(HostProvisioningError::FileNotFound(file_name.to_string()))
        }
    }

    /// Register program
    fn register_program(&mut self, client_id: u64, file_name: &str, prog: &[u8]) -> Result<(), HostProvisioningError> {
        //TODO: link to the actually fs API.
        //TODO: THIS ONLY IS GLUE CODE FOR NOW!
        Ok(())
    }

    /// Registers the program result.
    #[inline]
    pub(crate) fn set_result(&mut self, result: &[u8]) {
        self.result = Some(result.to_vec());
    }

    /// Registers the previous result.
    /// If the previous computation does not produce any result, ie returning none,
    /// it is converted to an empty vector.
    /// This distinguishes from `None`, which indicates that it is the first round of computation.
    #[inline]
    pub(crate) fn set_previous_result(&mut self, result: &Option<Vec<u8>>) {
        self.previous_result = Some(
            result
                .as_ref()
                .unwrap_or(&vec![])
                .to_vec(),
        );
    }

    /// Registers the number of expected data sources, `number`.
    #[inline]
    pub(crate) fn set_expected_data_sources(&mut self, number: &[u64]) -> &mut Self {
        self.expected_data_sources = number.to_vec();
        self
    }

    /// Registers the number of expected stream sources, `number`.
    #[inline]
    pub(crate) fn set_expected_stream_sources(&mut self, number: &[u64]) -> &mut Self {
        self.expected_stream_sources = number.to_vec();
        self
    }

    /// Registers the number of expected data sources, `number`.
    #[inline]
    pub(crate) fn set_expected_shutdown_sources(&mut self, client_ids: &[u64]) -> &mut Self {
        self.expected_shutdown_sources = client_ids.to_vec();
        self
    }

    /// Registers the program module.
    #[inline]
    pub(crate) fn set_program_module(&mut self, module: Module) {
        self.program_module = Some(module);
    }

    /// Registers the program digest.
    #[inline]
    pub(crate) fn set_program_digest(&mut self, digest: &[u8]) {
        self.program_digest = Some(digest.to_vec());
    }

    /// Registers a linear memory/heap.
    #[inline]
    pub(crate) fn set_memory(&mut self, memory: Memory) {
        self.memory = Some(memory);
    }

    ////////////////////////////////////////////////////////////////////////////
    // Querying the host state.
    ////////////////////////////////////////////////////////////////////////////

    /// Returns the current state of the provisioning process.
    #[inline]
    pub(crate) fn get_lifecycle_state(&self) -> &LifecycleState {
        self.lifecycle_state.borrow()
    }

    /// Returns the data sources that the provisioning process is expecting.
    #[inline]
    pub(crate) fn get_expected_data_sources(&self) -> &Vec<u64> {
        &self.expected_data_sources
    }

    /// Returns the number of data sources that the provisioning process is
    /// expecting.
    #[inline]
    pub(crate) fn get_expected_data_source_count(&self) -> usize {
        self.expected_data_sources.len()
    }

    /// Returns the number of data sources that have been provisioned so far.
    #[inline]
    pub(crate) fn get_current_data_source_count(&self) -> usize {
        self.data_sources.len()
    }

    /// Returns the stream sources that the provisioning process is expecting.
    #[inline]
    pub(crate) fn get_expected_stream_sources(&self) -> &Vec<u64> {
        &self.expected_stream_sources
    }

    /// Returns the number of stream sources that the provisioning process is expecting.
    #[inline]
    pub(crate) fn get_expected_stream_source_count(&self) -> usize {
        self.expected_stream_sources.len()
    }

    /// Returns that number of stream sources that have been provisioned so far.
    #[inline]
    pub(crate) fn get_current_stream_source_count(&self) -> usize {
        self.stream_sources.len()
    }

    /// Returns the program digest, if it has been computed.  Returns `None` iff
    /// the digest has not yet been computed.
    #[inline]
    pub(crate) fn get_program_digest(&self) -> Option<&Vec<u8>> {
        self.program_digest.as_ref()
    }

    /// Returns the data source frame (containing raw data, source and package
    /// IDs) associated with the Nth registered data source as stored in the
    /// host provisioning state, expressed by `index`.  Returns `None` iff
    /// `index` is not the index of any registered data source.
    pub(crate) fn get_current_data_source(&self, index: usize) -> Option<&DataSourceMetadata> {
        if index > self.get_current_data_source_count() {
            return None;
        }
        Some(&self.data_sources[index])
    }

    /// Returns the data source frame (containing raw data, source and package
    /// IDs) associated with the Nth registered data source as stored in the
    /// host provisioning state, expressed by `index`.  Returns `None` iff
    /// `index` is not the index of any registered data source.
    pub(crate) fn get_current_stream_source(&self, index: usize) -> Option<&DataSourceMetadata> {
        if index > self.get_current_stream_source_count() {
            return None;
        }
        Some(&self.stream_sources[index])
    }

    /// Returns the data source frame (containing raw data, source and package
    /// IDs) associated with the Nth registered data source as stored in the
    /// host provisioning state, expressed by `index`.  Returns `None` iff
    /// `index` is not the index of any registered data source.
    pub(crate) fn get_previous_result(&self) -> Option<&Vec<u8>> {
        self.previous_result.as_ref()
    }

    /// Returns the client IDs of clients who are able to request platform
    /// shutdown, per the global policy.
    #[inline]
    pub(crate) fn get_expected_shutdown_sources(&self) -> &Vec<u64> {
        self.expected_shutdown_sources.borrow()
    }

    /// Returns `true` iff a program module has been registered by the
    /// provisioning process.
    #[inline]
    pub(crate) fn is_program_registered(&self) -> bool {
        match &self.program_module {
            None => false,
            Some(_module) => true,
        }
    }

    /// Returns `true` iff a program's memory is registered by the provisioning
    /// process.
    #[inline]
    pub(crate) fn is_memory_registered(&self) -> bool {
        match &self.memory {
            None => false,
            Some(_memory) => true,
        }
    }

    /// Returns `true` iff a result has been written by the executing program.
    #[inline]
    pub(crate) fn is_result_registered(&self) -> bool {
        self.result != None
    }

    #[inline]
    pub(crate) fn is_able_to_shutdown(&self) -> bool {
        self.expected_shutdown_sources.is_empty()
    }

    /// Returns an optional result computed by the WASM program when it has
    /// finished executing.
    #[inline]
    pub(crate) fn get_result(&self) -> Option<&Vec<u8>> {
        self.result.as_ref()
    }

    /// Returns an optional reference to the WASM program module.
    #[inline]
    pub(crate) fn get_program(&self) -> Option<&Module> {
        self.program_module.as_ref()
    }

    /// Returns an optional reference to the WASM program's heap.
    #[inline]
    pub(crate) fn get_memory(&self) -> Option<&Memory> {
        self.memory.as_ref()
    }

    ////////////////////////////////////////////////////////////////////////////
    // Progressing through the state machine.
    ////////////////////////////////////////////////////////////////////////////
    // The state transition, where events, [...], and conditions, <...>, are either above or left to the edges.
    //
    //                   Initial (State)
    //                        |
    //                        | [Provisioning a program]
    //     <No data>          |
    //    --------------------| 
    //    |                   | <Need data>
    //    |                   |
    //    |                  \ /
    //    |             DataSourcesLoading  <-------------------
    //    |                   |                                |
    //    |                   | [Provisioning a (static) data  | 
    //    |                   |                                |
    //    |                   | <More data>                    |
    //    |                   |---------------------------------
    //    ------------------->|
    //                        | <-------------------------------
    //     <No stream>        |                                |
    //    --------------------|                                |
    //    |                   | [Need stream]                  |
    //    |                   |                                |
    //    |                  \ /                               |
    //    |           StreamSourcesLoading  <----------------- |
    //    |                   |                              | |
    //    |                   | [Provisioning a stream data] | |
    //    |                   |                              | |
    //    |                   | <More stream>                | |
    //    |                   |------------------------------- |
    //    ------------------->|                                |
    //                        |                                |
    //                       \ /                               |
    //                ReadyToExecute                           |
    //                        |                                |
    //                        | [Request result]               |
    //                        |                                |
    //                       \ /                               |
    // ------------>  FinishedExecuting  <----------           |
    // |                      |                    |           |
    // |                      |                    |           |
    // |                      | [Request result]   |           |
    // |                      |---------------------           |
    // |                      |                                |
    // |                      | [Request next round]           |
    // |                      |---------------------------------
    // |                      |
    // |   [Request shutdown] |
    // |                      | 
    // | <More shutdown req>  | 
    // -----------------------| 
    //                        | <All shutdown requests received>
    //                        |
    //                       \ /
    //                   Bottom state
    //   
    //
    
    /// Sets the machine state to `MachineState::Error`.
    ///
    /// Does not panic: an error state can be reached from any Veracruz state
    /// and once in an error state you can never get back out.
    #[inline]
    pub(crate) fn set_error(&mut self) {
        self.lifecycle_state = LifecycleState::Error;
    }

    /// Sets the machine state to `LifecycleState::ReadyToExecute`.
    ///
    /// PANICS: will panic if the current machine state is neither
    /// `LifecycleState::Initial`, `LifecycleState::DataSourcesLoading` nor `LifecycleState::StreamSourcesLoading`.
    #[inline]
    pub(crate) fn set_ready_to_execute(&mut self) {
        // This should have been checked before now, to provide a more
        // meaningful error.  This is here just to ensure nothing slips through,
        // and if it does, terminate.
        assert!(
            self.lifecycle_state == LifecycleState::Initial
                || self.lifecycle_state == LifecycleState::DataSourcesLoading
                || self.lifecycle_state == LifecycleState::StreamSourcesLoading
        );
        self.lifecycle_state = LifecycleState::ReadyToExecute;
    }

    /// Sets the machine state to `LifecycleState::DataSourcesLoading`.
    ///
    /// PANICS: will panic if the current machine state is neither
    /// `LifecycleState::Initial` nor `LifecycleState::DataSourcesLoading`.
    #[inline]
    pub(crate) fn set_data_sources_loading(&mut self) {
        // This should have been checked before now, to provide a more
        // meaningful error.  This is here just to ensure nothing slips through,
        // and if it does, terminate.
        assert!(
            self.lifecycle_state == LifecycleState::DataSourcesLoading
                || self.lifecycle_state == LifecycleState::Initial
        );
        self.lifecycle_state = LifecycleState::DataSourcesLoading;
    }

    /// Sets the machine state to `LifecycleState::DataSourcesLoading`.
    ///
    /// PANICS: will panic if the current machine state is neither
    /// `LifecycleState::Initial` nor `LifecycleState::DataSourcesLoading`.
    #[inline]
    pub(crate) fn set_stream_sources_loading(&mut self) {
        // This should have been checked before now, to provide a more
        // meaningful error.  This is here just to ensure nothing slips through,
        // and if it does, terminate.
        assert!(
            self.lifecycle_state == LifecycleState::StreamSourcesLoading
                || self.lifecycle_state == LifecycleState::DataSourcesLoading
                || self.lifecycle_state == LifecycleState::Initial
        );
        self.lifecycle_state = LifecycleState::StreamSourcesLoading;
    }

    /// Sets the machine state to `LifecycleState::FinishedExecuting`.
    ///
    /// PANICS: will panic if the current machine state is not
    /// `LifecycleState::ReadyToExecute`.
    #[inline]
    pub(crate) fn set_finished_executing(&mut self) {
        // This should have been checked before now, to provide a more
        // meaningful error.  This is here just to ensure nothing slips through,
        // and if it does, terminate.
        assert_eq!(self.lifecycle_state, LifecycleState::ReadyToExecute);
        self.lifecycle_state = LifecycleState::FinishedExecuting;
    }

    ////////////////////////////////////////////////////////////////////////////
    // Registering data sources.
    ////////////////////////////////////////////////////////////////////////////

    /// Sort the input data provided to the host to match the order specified in
    /// the policy file.
    fn sort_incoming_data(&mut self) -> Result<(), HostProvisioningError> {
        Self::sorting_functor(&mut self.data_sources, &self.expected_data_sources)
    }

    /// Registers the data source `metadata`` in the host state.  Host state
    /// must be in the state `LifecycleState::DataSourcesLoading` otherwise an
    /// error is returned.  Progresses the provisioning process to either
    /// - `LifecycleState::ReadyToExecute` if all data sources are loaded on
    /// completion of this call, and stream data is NOT required
    /// -  `LifecycleState::StreamSourcesLoading` if all data sources are loaded on
    /// completion of this call, and stream data is required
    /// - or `LifecycleState::DataSourcesLoading` if more
    /// data sources need to be loaded.
    ///
    /// PANICS: if the invariant that we are only ever in
    /// `LifecycleState::DataSourcesLoading` whenever we still have data left to
    /// load is broken.
    pub(crate) fn add_new_data_source(
        &mut self,
        metadata: DataSourceMetadata,
    ) -> Result<(), HostProvisioningError> {
        match self.get_lifecycle_state() {
            LifecycleState::DataSourcesLoading => {
                let expected_data_sources = self.get_expected_data_source_count();
                /* This is an invariant checking guard: we should not be still
                 * in LifecycleState::DataSourcesLoading if we have all the data
                 * that we need --- we should have moved into
                 * LifecycleState::ReadyToExecute or LifecycleState::StreamSourcesLoading by now!
                 */
                assert!(self.get_current_data_source_count() < expected_data_sources);

                self.data_sources.push(metadata);

                /* If we have loaded everything, bunp the state and sort the
                 * incoming data, otherwise remain in the data sources loading
                 * state and signal success.
                 */
                if self.get_current_data_source_count() == expected_data_sources {
                    if self.get_expected_stream_source_count() == 0 {
                        self.set_ready_to_execute();
                    } else {
                        self.set_stream_sources_loading();
                    }
                    self.sort_incoming_data()
                } else {
                    Ok(())
                }
            }
            otherwise => Err(HostProvisioningError::InvalidLifeCycleState {
                expected: vec![LifecycleState::DataSourcesLoading],
                found: otherwise.clone(),
            }),
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    // Registering stream sources.
    ////////////////////////////////////////////////////////////////////////////

    /// Sort the input stream provided to the host to match the order specified in
    /// the policy file.
    fn sort_incoming_stream(&mut self) -> Result<(), HostProvisioningError> {
        Self::sorting_functor(&mut self.stream_sources, &self.expected_stream_sources)
    }

    /// Registers the data source [`metadata`] in the host state.  Host state must be in
    /// the state [`MachineState::DataSourcesLoading`] otherwise an error is returned.
    /// Progresses the provisioning process to either [`MachineState::ReadyToExecute`] if
    /// all data sources are loaded on completion of this call, or
    /// [`MachineState::DataSourcesLoading`] if more data sources need to be loaded.
    ///
    ///
    /// Registers the stream source `metadata`` in the host state.  Host state
    /// must be in the state `LifecycleState::StreamSourcesLoading` otherwise an
    /// error is returned.  Progresses the provisioning process to either
    /// `LifecycleState::ReadyToExecute` if all stream sources are loaded on
    /// completion of this call, or `LifecycleState::StreamSourcesLoading` if more
    /// data sources need to be loaded.
    ///
    /// PANICS: if the invariant that we are only ever in
    /// `LifecycleState::StreamSourcesLoading` whenever we still have data left to
    /// load is broken.
    pub(crate) fn add_new_stream_source(
        &mut self,
        metadata: DataSourceMetadata,
    ) -> Result<(), HostProvisioningError> {
        match self.get_lifecycle_state() {
            LifecycleState::StreamSourcesLoading => {
                let expected_stream_sources = self.get_expected_stream_source_count();
                /* This is an invariant checking guard: we should not be still
                 * in LifecycleState::StreamSourcesLoading if we have all the data
                 * that we need --- we should have moved into
                 * LifecycleState::ReadyToExecute by now!
                 */
                assert!(self.get_current_stream_source_count() < expected_stream_sources);

                self.stream_sources.push(metadata);

                /* If we have loaded everything, bunp the state and sort the
                 * incoming data, otherwise remain in the data sources loading
                 * state and signal success.
                 */
                if self.get_current_stream_source_count() == expected_stream_sources {
                    self.set_ready_to_execute();
                    self.sort_incoming_stream()
                } else {
                    Ok(())
                }
            }
            otherwise => Err(HostProvisioningError::InvalidLifeCycleState {
                expected: vec![LifecycleState::StreamSourcesLoading],
                found: otherwise.clone(),
            }),
        }
    }

    /// Sort the incoming data against pattern, against the expected_data_sources provided in the policy file
    fn sorting_functor(
        data: &mut Vec<DataSourceMetadata>,
        pattern: &Vec<u64>,
    ) -> Result<(), HostProvisioningError> {
        // pre-sort the incoming data by client id then package id
        data.sort_by(|lhs, rhs| {
            lhs.client_id
                .cmp(&rhs.client_id)
                .then_with(|| lhs.package_id.cmp(&rhs.package_id))
        });

        // Iterate over pattern.
        // In each iteration, search the next package in `data` and add the result to
        // `new_data_sources`. Variable `previous_packages` tracks the previous package_id for each
        // client, initially being undefined and then updated in each iteration.
        let mut new_data_sources: std::vec::Vec<DataSourceMetadata> = Vec::new();
        let mut previous_packages: std::collections::HashMap<u64, u64> = HashMap::new();
        for next_client_id in pattern.iter() {
            let next_package_iter = match previous_packages.get(&next_client_id) {
                Some(previous_package_id) => data.iter().find(|data_item| {
                    data_item.client_id == *next_client_id
                        && data_item.package_id > *previous_package_id
                }),
                None => {
                    // because the data_sources is sorted, the first package in the vec for client_id will be the first package
                    data.iter()
                        .find(|data_item| data_item.client_id == *next_client_id)
                }
            };

            match next_package_iter {
                Some(next_package) => {
                    previous_packages.insert(*next_client_id, next_package.package_id);

                    new_data_sources.push(DataSourceMetadata {
                        data: next_package.data.iter().cloned().collect(),
                        client_id: next_package.client_id,
                        package_id: next_package.package_id,
                    });
                }
                None => {
                    return Err(HostProvisioningError::CannotSortDataOrStream);
                }
            };
        }
        *data = new_data_sources;
        Ok(())
    }

    ////////////////////////////////////////////////////////////////////////////
    // Requesting shutdown.
    ////////////////////////////////////////////////////////////////////////////

    /// Signals to the provisioning host that a client has requested shutdown.
    #[inline]
    pub(crate) fn request_shutdown(&mut self, client_id: u64) {
        self.expected_shutdown_sources.retain(|v| v != &client_id);
    }
}

////////////////////////////////////////////////////////////////////////////////
// Fatal host errors
////////////////////////////////////////////////////////////////////////////////

/// A fatal, runtime error that terminates the Veracruz host immediately.  This
/// is akin to a "kernel panic" for Veracruz: these errors are not passed to the
/// WASM program running on the platform, but are instead fundamental issues
/// that require immediate shutdown as they cannot be fixed.
///
/// *NOTE*: care should be taken when presenting these errors to users when in
/// release (e.g. not in debug) mode: they can give away a lot of information
/// about what is going on inside the enclave.
#[derive(Debug, Error, Serialize, Deserialize)]
pub enum FatalHostError {
    /// The Veracruz host was passed bad arguments by the WASM program running
    /// on the platform.  This should never happen if the WASM program uses
    /// `libveracruz` as the platform should ensure H-Calls are always
    /// well-formed.  Seeing this either indicates a bug in `libveracruz` or a
    /// programming error in the source that originated the WASM programming if
    /// `libveracruz` was not used.
    #[error(
        display = "FatalVeracruzHostError: Bad arguments passed to host function '{}'.",
        function_name
    )]
    BadArgumentsToHostFunction {
        //NOTE: use `String` instead of `&'static str` to make serde happy.
        /// The name of the host function that was being invoked.
        function_name: String,
    },
    /// The WASM program tried to invoke an unknown H-call on the Veracruz host.
    #[error(
        display = "FatalVeracruzHostError: Unknown H-call invoked: '{}'.",
        index
    )]
    UnknownHostFunction {
        /// The host call index of the unknown function that was invoked.
        index: usize,
    },
    /// The host failed to read a range of bytes, starting at a base address,
    /// from the running WASM program's linear memory.
    #[error(
        display = "FatalVeracruzHostError: Failed to read {} byte(s) from WASM memory at address {}.",
        bytes_to_be_read,
        memory_address
    )]
    MemoryReadFailed {
        /// The base memory address that was being read.
        memory_address: usize,
        /// The number of bytes that were being read.
        bytes_to_be_read: usize,
    },
    /// The host failed to write a range of bytes, starting from a base address,
    /// to the running WASM program's linear memory.
    #[error(
        display = "FatalVeracruzHostError: Failed to write {} byte(s) to WASM memory at address {}.",
        bytes_to_be_written,
        memory_address
    )]
    MemoryWriteFailed {
        /// The base memory address that was being written.
        memory_address: usize,
        /// The number of bytes that were being written.
        bytes_to_be_written: usize,
    },
    /// No linear memory was registered: this is a programming error (a bug)
    /// that should be fixed.
    #[error(display = "FatalVeracruzHostError: No WASM memory registered.")]
    NoMemoryRegistered,
    /// No program module was registered: this is a programming error (a bug)
    /// that should be fixed.
    #[error(display = "FatalVeracruzHostError: No WASM program module registered.")]
    NoProgramModuleRegistered,
    /// The WASM program's entry point was missing or malformed.
    #[error(
        display = "FatalVeracruzHostError: Failed to find the entry point in the WASM program."
    )]
    NoProgramEntryPoint,
    /// The WASM program's entry point was missing or malformed.
    #[error(display = "FatalVeracruzHostError: Execution engine is not ready.")]
    EngineIsNotReady,
    /// Wrapper for direct error message.
    #[error(display = "FatalVeracruzHostError: WASM program returns code other than i32.")]
    ReturnedCodeError,
    /// Wrapper for WASI Trap.
    #[error(display = "FatalVeracruzHostError: WASMIError: Trap: {:?}.", _0)]
    WASMITrapError(#[source(error)] wasmi::Trap),
    /// Wrapper for WASI Error other than Trap.
    #[error(display = "FatalVeracruzHostError: WASMIError {:?}.", _0)]
    WASMIError(#[source(error)] wasmi::Error),
    /// Wrapper for direct error message.
    #[error(display = "FatalVeracruzHostError: Error message {:?}.", _0)]
    DirectErrorMessage(String),
    /// Something unknown or unexpected went wrong, and there's no more detailed
    /// information.
    #[error(display = "FatalVeracruzHostError: Unknown error.")]
    Generic,
}

impl From<String> for FatalHostError {
    fn from(err: String) -> Self {
        FatalHostError::DirectErrorMessage(err)
    }
}

impl From<&str> for FatalHostError {
    fn from(err: &str) -> Self {
        FatalHostError::DirectErrorMessage(err.to_string())
    }
}

////////////////////////////////////////////////////////////////////////////////
// Implementation of the H-calls.
////////////////////////////////////////////////////////////////////////////////

/// The return type for H-Call implementations.
///
/// From *the viewpoint of the host* a H-call can either fail spectacularly
/// with a runtime trap, in which case `Err(err)` is returned, with `err`
/// detailing what went wrong, and the Veracruz host thereafter terminating
/// or otherwise entering an error state, or succeeds with `Ok(())`.
///
/// From *the viewpoint of the WASM program* a H-call can either fail
/// spectacularly, as above, in which case WASM program execution is aborted
/// with the WASM program itself not being able to do anything about this,
/// succeeds with the desired effect and a success error code returned, or
/// fails with a recoverable error in which case the error code details what
/// went wrong and what can be done to fix it.
pub(crate) type HCallError = Result<VeracruzError, FatalHostError>;

/// Details the arguments expected by the module's entry point, if any is found.
pub(crate) enum EntrySignature {
    /// The expected entry point (e.g. "main") is not found in the WASM module
    /// or it was found and it did not have a recognisable type signature.
    NoEntryFound,
    /// The entry point does not expect any parameters.
    NoParameters,
    /// The entry point expects a dummy `argv` and an `argc` to be supplied.
    ArgvAndArgc,
}

////////////////////////////////////////////////////////////////////////////////
// The strategy trait.
////////////////////////////////////////////////////////////////////////////////

/// This is what an execution strategy exposes to clients outside of this
/// library.  This functionality is sufficient to implement both
/// `freestanding-execution-engine` and `runtime-manager` and if any functionality is
/// missing that these components require then it should be added to this trait
/// and implemented for all supported implementation strategies.
///
/// Note that a factory method, in the file `hcall/factory.rs` will return an
/// opaque instance of this trait depending on the
pub trait ExecutionEngine: Send {
    //TODO: these API will be replaced by FS API -- strart
    /// Append `buf` to `file_name` in the file system
    /// on behalf of the client identified by `client_id`.
    /// The client must has the write permission to the file.
    /// It createa a new file, if the file does not exists.
    fn append_file(&mut self, client_id: u64, file_name: &str, data: &[u8]) -> Result<(), HostProvisioningError>;

    /// Read `file_name` in the file system
    /// on behalf of the client identified by `client_id`.
    /// The client must has the read permission to the file.
    /// It createa a new file, if the file does not exists.
    ///
    /// TODO: Add the range selector
    fn read_file(&self, client_id: u64, file_name: &str) -> Result<Option<Vec<u8>>, HostProvisioningError>;

    /// Register a program `file_name` 
    /// on behalf of the client identified by `client_id`.
    /// The client must has the read permission to `file_name`.
    /// This program must be specified in the permission system
    /// and the hash of `prog` must match the requirement.
    fn register_program(&mut self, client_id: u64, file_name: &str, prog: &[u8]) -> Result<(), HostProvisioningError>; 

    //TODO: these API will be replaced by FS API -- strart
    /// Loads a raw WASM program from a buffer of received or parsed bytes.
    /// Will fail if the lifecycle state is not in `LifecycleState::Initial` or
    /// if the buffer cannot be parsed.  On success bumps the lifecycle state to
    /// `LifecycleState::ReadyToExecute` in cases where no data sources are
    /// expected (i.e. we are a pure delegate) or
    /// `LifecycleState::DataSourcesLoading` in cases where we are expecting
    /// data to be provisioned.
    fn load_program(&mut self, buffer: &[u8]) -> Result<(), HostProvisioningError>;

    /// Provisions a new data source, described using a `DataSourceMetadata`
    /// frame into the host state.  Will fail if the lifecycle state is not
    /// `LifecycleState::DataSourcesLoading`.  Will bump the lifecycle state to
    /// `LifecycleState::ReadyToExecute` when the call represents the last
    /// data source to be loaded, or maintains the current lifecycle state.
    fn add_new_data_source(
        &mut self,
        metadata: DataSourceMetadata,
    ) -> Result<(), HostProvisioningError>;

    /// Provisions a new stream source, described using a `DataSourceMetadata`
    /// frame into the host state.  Will fail if the lifecycle state is not
    /// `LifecycleState::DataSourcesLoading`.  Will bump the lifecycle state to
    /// `LifecycleState::ReadyToExecute` when the call represents the last
    /// data source to be loaded, or maintains the current lifecycle state.
    fn add_new_stream_source(
        &mut self,
        metadata: DataSourceMetadata,
    ) -> Result<(), HostProvisioningError>;
    //TODO: these API will be replaced by FS API -- end

    /// Invokes the entry point of the provisioned WASM program.  Will fail if
    /// the current lifecycle state is not `LifecycleState::ReadyToExecute` or
    /// if the WASM program fails at runtime.  On success, bumps the lifecycle
    /// state to `LifecycleState::FinishedExecuting` and returns the error code
    /// returned by the WASM program entry point as an `i32` value.
    fn invoke_entry_point(&mut self, file_name: &str) -> Result<i32, FatalHostError>;

    //TODO: do we need this 
    /// Returns `true` iff a program module has been registered in the host
    /// provisioning state.
    fn is_program_registered(&self) -> bool;

    //TODO: do we need this 
    /// Returns `true` iff a result has been registered with the host
    /// provisioning state by a WASM program.
    fn is_result_registered(&self) -> bool;

    //TODO: do we need this 
    /// Returns `true` iff a memory is registered with the host provisioning
    /// state from the program module.
    fn is_memory_registered(&self) -> bool;

    /// Returns `true` iff all clients who must request shutdown have now done
    /// so.
    fn is_able_to_shutdown(&self) -> bool;

    /// Returns the current lifecycle state that the host provisioning state is
    /// in.
    fn get_lifecycle_state(&self) -> LifecycleState;

    //TODO: do we need this 
    /// Returns the current number of data sources provisioned into the host
    /// provisioning state.
    fn get_current_data_source_count(&self) -> usize;

    //TODO: do we need this 
    /// Returns the expected data sources, as identified by their client IDs,
    /// that we expect to be provisioned into the host state.
    fn get_expected_data_sources(&self) -> Vec<u64>;

    //TODO: do we need this 
    /// Returns the list of client IDs of clients who can request shutdown of
    /// the platform.
    fn get_expected_shutdown_sources(&self) -> Vec<u64>;

    //TODO: do we need this 
    /// Returns the current number of stream sources provisioned into the host
    /// provisioning state.
    fn get_current_stream_source_count(&self) -> usize;

    //TODO: do we need this 
    /// Returns the expected stream sources, as identified by their client IDs,
    /// that we expect to be provisioned into the host state.
    fn get_expected_stream_sources(&self) -> Vec<u64>;

    //TODO: do we need this 
    /// Returns a result of a WASM computation that has executed on the host
    /// provisioning state.  Returns `None` iff no such result has been
    /// registered.
    fn get_result(&self) -> Option<Vec<u8>>;

    //TODO: do we need this 
    /// Returns an SHA-256 digest of the bytes loaded into the host provisioning
    /// state.  Returns `None` iff no such program has yet been loaded.
    fn get_program_digest(&self) -> Option<Vec<u8>>;

    //TODO: do we need this 
    /// Sets the expected data sources, through a list of their source IDs, that
    /// this computation is expecting.
    fn set_expected_data_sources(&mut self, sources: &[u64]) -> &mut dyn ExecutionEngine;

    //TODO: do we need this 
    /// Sets the expected stream sources, through a list of their source IDs, that
    /// this computation is expecting.
    fn set_expected_stream_sources(&mut self, sources: &[u64]) -> &mut dyn ExecutionEngine;

    //TODO: do we need this 
    /// Sets the expected shutdown sources, through a list of their source IDs, that
    /// this computation is expecting.
    fn set_expected_shutdown_sources(&mut self, sources: &[u64]) -> &mut dyn ExecutionEngine;

    //TODO: do we need this 
    /// Registers the previous result.
    fn set_previous_result(&mut self, result: &Option<Vec<u8>>);

    /// Moves the host provisioning state's lifecycle state into
    /// `LifecycleState::Error`, a state which it cannot ever escape,
    /// effectively invalidating it.
    fn invalidate(&mut self);

    /// Signals that a client would like to shutdown the platform.  Has no
    /// effect is `client_id` does not correspond to a client with the shutdown
    /// role.
    fn request_shutdown(&mut self, client_id: u64);

    ////////////////////////////////////////////////////////////////////////////
    // Derived code.
    ////////////////////////////////////////////////////////////////////////////

    /// Returns `true` iff the host state is in one of a number of expected
    /// states passed as the second argument, `states`.
    #[inline]
    fn is_in_expected_state(&self, states: &[LifecycleState]) -> bool {
        states
            .iter()
            .any(|sigma| sigma == &self.get_lifecycle_state())
    }

    /// Requests shutdown on behalf of a client, as identified by their client
    /// ID, and then checks if this request was sufficient to reach a threshold
    /// of requests wherein the platform can finally shutdown.
    fn request_and_check_shutdown(&mut self, client_id: u64) -> bool {
        self.request_shutdown(client_id);
        self.is_able_to_shutdown()
    }
}

////////////////////////////////////////////////////////////////////////////////
// Trait implementations
////////////////////////////////////////////////////////////////////////////////

/// Serialize a `LifecycleState` value to a `u8`.
///
/// This is needed for responding to the Veracruz protocol "query enclave state"
/// request from a computation principal.  The current state is encoded as a
/// `u8` and forwarded to the requestor.
impl From<LifecycleState> for u8 {
    fn from(state: LifecycleState) -> Self {
        match state {
            LifecycleState::Initial => 0,
            LifecycleState::DataSourcesLoading => 1,
            LifecycleState::StreamSourcesLoading => 2,
            LifecycleState::ReadyToExecute => 3,
            LifecycleState::FinishedExecuting => 4,
            LifecycleState::Error => 5,
        }
    }
}

/// Serialize a `&LifecycleState` value to a `u8`.
///
/// This is needed for responding to the Veracruz protocol "query enclave state"
/// request from a computation principal.  The current state is encoded as a
/// `u8` and forwarded to the requestor.
impl From<&LifecycleState> for u8 {
    fn from(state: &LifecycleState) -> Self {
        match state {
            LifecycleState::Initial => 0,
            LifecycleState::DataSourcesLoading => 1,
            LifecycleState::StreamSourcesLoading => 2,
            LifecycleState::ReadyToExecute => 3,
            LifecycleState::FinishedExecuting => 4,
            LifecycleState::Error => 5,
        }
    }
}

/// Converts a `u8` value to a `LifecycleState`, if possible.
///
/// This is needed for understanding the response to the Veracruz protocol
/// "query enclave state" message made by a computation principal.  The current
/// state is encoded as a `u8` and forwarded, which can then be decoded using
/// this.
impl TryFrom<u8> for LifecycleState {
    type Error = ();

    fn try_from(code: u8) -> Result<Self, ()> {
        match code {
            0 => Ok(LifecycleState::Initial),
            1 => Ok(LifecycleState::DataSourcesLoading),
            2 => Ok(LifecycleState::StreamSourcesLoading),
            3 => Ok(LifecycleState::ReadyToExecute),
            4 => Ok(LifecycleState::FinishedExecuting),
            5 => Ok(LifecycleState::Error),
            _otherwise => Err(()),
        }
    }
}
