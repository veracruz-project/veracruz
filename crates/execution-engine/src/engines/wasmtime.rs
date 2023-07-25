//! An implementation of the ExecutionEngine runtime state for Wasmtime.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Copyright
//!
//! See the file `LICENSE.md` in the Veracruz root directory for licensing
//! and copyright information.

#![allow(clippy::too_many_arguments)]

use crate::{
    engines::common::{
        Bound, BoundMut, EntrySignature, ExecutionEngine, MemoryHandler,
        MemorySlice, MemorySliceMut, WasiWrapper,
    },
    fs::{FileSystem, FileSystemResult},
    Options,
};
use anyhow::Result;
use log::info;
use std::{
    convert::TryFrom,
    mem,
    vec::Vec,
};
use wasi_types::ErrNo;
use wasmtime::{
    AsContext, AsContextMut, Caller, Config, Engine, ExternType, Linker, Memory, Module, Store,
    StoreContext, StoreContextMut, ValType,
};
use wasmtime::*;
use wasmtime_wasi::{WasiCtx, sync::{Dir, WasiCtxBuilder}};
use std::path::Path;
use std::fs::File;

////////////////////////////////////////////////////////////////////////////////
// The Wasmtime runtime state.
////////////////////////////////////////////////////////////////////////////////

/// An implementation of MemorySlice for Wasmtime.
///
/// We use `data` function in Memory.
/// Conveniently, Memory is managed by internal reference counting, and already
/// isn't thread-safe, so we don't have to worry too much about the complex
/// lifetime requirements of MemorySlice.
pub struct WasmtimeSlice<'a, T> {
    store: StoreContext<'a, T>,
    memory: Memory,
    address: usize,
    length: usize,
}

/// An implementation of MemorySliceMut for Wasmtime.
///
/// We use `data_mut` function in Memory.
/// Conveniently, Memory is managed by internal reference counting, and already
/// isn't thread-safe, so we don't have to worry too much about the complex
/// lifetime requirements of MemorySlice.
pub struct WasmtimeSliceMut<'a, T> {
    store: StoreContextMut<'a, T>,
    memory: Memory,
    address: usize,
    length: usize,
}

/// Implementation of AsRef<u8> for  WasmtimeSlice. Implementation of Wasi is able to use this
/// function to access the linear memory in Wasmtime.
impl<'a, T> AsRef<[u8]> for WasmtimeSlice<'a, T> {
    fn as_ref(&self) -> &[u8] {
        // NOTE this is currently unsafe, but has a safe variant in recent
        // versions of wasmtime
        &(self.memory.data(&self.store))[self.address..self.address + self.length]
    }
}

/// Implementation of AsMut<u8> for  WasmtimeSlice. Implementation of Wasi is able to use this
/// function to access the linear memory in Wasmtime.
impl<'a, T> AsMut<[u8]> for WasmtimeSliceMut<'a, T> {
    fn as_mut(&mut self) -> &mut [u8] {
        // NOTE this is currently unsafe, but has a safe variant in recent
        // versions of wasmtime
        &mut (self.memory.data_mut(&mut self.store))[self.address..self.address + self.length]
    }
}

impl<T> MemorySlice for WasmtimeSlice<'_, T> {}
impl<T> MemorySliceMut for WasmtimeSliceMut<'_, T> {}

/// Impl the MemoryHandler for Caller.
/// This allows passing the Caller to WasiWrapper on any VFS call. Implementation
/// here is *NOT* thread-safe, if multiple threads manipulate this Wasmtime instance.
impl<'a, T: 'static> MemoryHandler for Caller<'a, T> {
    type Slice = WasmtimeSlice<'static, T>;
    type SliceMut = WasmtimeSliceMut<'static, T>;

    fn get_slice<'b>(
        &'b self,
        address: u32,
        length: u32,
    ) -> FileSystemResult<Bound<'b, Self::Slice>> {
        // NOTE: manually and temporarily change the mutability.
        // The unwrap will fail only if the raw pointer is null, which never happens here.
        let memory = match unsafe { (self as *const Self as *mut Self).as_mut() }
            .unwrap()
            .get_export(WasiWrapper::LINEAR_MEMORY_NAME)
            .and_then(|export| export.into_memory())
        {
            Some(s) => s,
            None => return Err(ErrNo::NoMem),
        };
        // Manually bend the lifetime to static. This can be improved when GAT
        // fully works in Rust standard.
        Ok(Bound::new(WasmtimeSlice {
            store: unsafe {
                mem::transmute::<StoreContext<'b, T>, StoreContext<'static, T>>(self.as_context())
            },
            memory,
            address: address as usize,
            length: length as usize,
        }))
    }

    fn get_slice_mut<'c>(
        &'c mut self,
        address: u32,
        length: u32,
    ) -> FileSystemResult<BoundMut<'c, Self::SliceMut>> {
        let memory = match self
            .get_export(WasiWrapper::LINEAR_MEMORY_NAME)
            .and_then(|export| export.into_memory())
        {
            Some(s) => s,
            None => return Err(ErrNo::NoMem),
        };
        // Manually bend the lifetime to static. This can be improved when GAT
        // fully works in Rust standard.
        Ok(BoundMut::new(WasmtimeSliceMut {
            store: unsafe {
                mem::transmute::<StoreContextMut<'c, T>, StoreContextMut<'static, T>>(
                    self.as_context_mut(),
                )
            },
            memory,
            address: address as usize,
            length: length as usize,
        }))
    }

    fn get_size(&self) -> FileSystemResult<u32> {
        // NOTE: manually and temporarily change the mutability.
        // Invocation of `unwrap` only fails if the raw pointer is NULL, but it never happens here.
        let memory = match unsafe { (self as *const Self as *mut Self).as_mut() }
            .unwrap()
            .get_export(WasiWrapper::LINEAR_MEMORY_NAME)
            .and_then(|export| export.into_memory())
        {
            Some(s) => s,
            None => return Err(ErrNo::NoMem),
        };
        Ok(u32::try_from(memory.data_size(&self)).unwrap())
    }
}

////////////////////////////////////////////////////////////////////////////////
// Checking function well-formedness.
////////////////////////////////////////////////////////////////////////////////

/// Checks whether `main` was declared with `argc` and `argv` or without in the
/// WASM program.
fn check_main(tau: &ExternType) -> EntrySignature {
    match tau {
        ExternType::Func(tau) => {
            let params: Vec<ValType> = tau.params().collect();

            if params == [ValType::I32, ValType::I32] {
                EntrySignature::ArgvAndArgc
            } else if params == [] {
                EntrySignature::NoParameters
            } else {
                EntrySignature::NoEntryFound
            }
        }
        _otherwise => EntrySignature::NoEntryFound,
    }
}

////////////////////////////////////////////////////////////////////////////////
// The Wasmtime host provisioning state.
////////////////////////////////////////////////////////////////////////////////
/// The facade of WASMTIME host provisioning state.
pub struct WasmtimeRuntimeState {
    ///// The WASI file system wrapper. It is a sharable structure protected by lock.
    ///// The common pattern is to clone it and try to lock it, to obtain the underlining
    ///// WasiWrapper.
    //filesystem: SharedMutableWasiWrapper,
}

////////////////////////////////////////////////////////////////////////////////
// Operations on the WasmtimeRuntimeState.
////////////////////////////////////////////////////////////////////////////////

impl WasmtimeRuntimeState {
    /// Creates a new initial `HostProvisioningState`.
    pub fn new(_filesystem: FileSystem, _options: Options) -> Result<Self> {
        Ok(Self {
            //filesystem: Arc::new(Mutex::new(WasiWrapper::new(filesystem, options)?)),
        })
    }

    /// Executes the entry point of the WASM program provisioned into the
    /// Veracruz host.
    ///
    /// Raises a panic if the global Wasmtime host is unavailable.
    /// Returns an error if no program is registered, the program is invalid,
    /// the program contains invalid external function calls or if the machine is not
    /// in the `LifecycleState::ReadyToExecute` state prior to being called.
    ///
    /// Also returns an error if the WASM program or the Veracruz instance
    /// create a runtime trap during program execution (e.g. if the program
    /// executes an abort instruction, or passes bad parameters to the Veracruz
    /// host).
    ///
    /// Otherwise, returns the return value of the entry point function of the
    /// program, along with a host state capturing the result of the program's
    /// execution.
    pub(crate) fn invoke_engine(&self, binary: Vec<u8>) -> Result<u32> {

        info!("Initialize a wasmtime engine.");

        let mut config = Config::default();
        config.wasm_simd(true);
        let engine = Engine::new(&config)?;
        // TODO
        // ADD all the linkere here 
        // https://docs.wasmtime.dev/examples-rust-wasi.html
        let mut linker = Linker::new(&engine);
        wasmtime_wasi::add_to_linker(&mut linker, |s| s)?;


        let path = Path::new(".");
        let file = match File::open(&path) {
            Err(why) => panic!("couldn't open file: {:?}", why),
            Ok(file) => {info!("could open `.`"); file},
        };  

        let wasi = WasiCtxBuilder::new()
            // https://docs.wasmtime.dev/api/wasmtime_wasi/sync/struct.WasiCtxBuilder.html#method.args
            //.args([....]) argument passed in
            .inherit_stdin()
            .inherit_stdout()
            .inherit_stderr()
            .inherit_stdio()
            //TODO add more
            .inherit_args()?
            .preopened_dir(Dir::from_std_file(file), "/")?
            .build();
        let mut store = Store::new(&engine, wasi);

        let module = Module::new(&engine, binary)?;

        linker.module(&mut store, "", &module)?;

        info!("Engine readies.");

        linker
            .get_default(&mut store, "")?
            .typed::<(), ()>(&store)?
            .call(&mut store, ())?;

        info!("Execution returns.");

        Ok(0)
    }
}

/// The `WasmtimeHostProvisioningState` implements everything needed to create a
/// compliant instance of `ExecutionEngine`.
impl ExecutionEngine for WasmtimeRuntimeState {
    /// ExecutionEngine wrapper of `invoke_engine`.  Raises a panic if
    /// the global Wasmtime host is unavailable.
    #[inline]
    fn invoke_entry_point(&mut self, program: Vec<u8>) -> Result<u32> {
        self.invoke_engine(program)
    }
}
