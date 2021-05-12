# Proposal for WASI ABI in Veracruz Execution Engine

This proposal includes: 

 * Moves to a named model, wherein inputs, outputs and programs are "file-like" stored in a 
   virtual file system (VFS) and have names set by policy. This makes programs more reusable and composable. 
 * Introduces a familiar file-oriented programming model for data IO. 
 * Moves to an incremental read/write model, wherein programs can incrementally
   read inputs into smaller buffers as they consume input, and incrementally
   write to outputs as they generate it.
 * Moves to a scatter-gather buffer management model, wherein programs can use
   ordered lists of smaller buffers in place of larger buffers. This reduces
   memory fragmentation pressure.

While not a primary motivation, this proposal additionally introduces new and
potentially easier and more powerful ways for Veracruz users to develop and
debug their programs.

## WASI ABI Summary

Implementation is based on the description in [wasi_snapshot_preview1][1].
However, the actual ABI definitions, particularly parameters, is slightly different, which can be found in 
[here](https://github.com/alexcrichton/rust-wasi/blob/master/src/wasi_unstable/raw.rs) or [here][2].
We use a fork of [wasi-type](https://github.com/veracruz-project/wasi-types) for all type definitions in [wasi_snapshot_preview1][1].

Notes:
 * All Veracruz program inputs and outputs exist as named entities that appear as
   file-like objects living in the root directory. All are accessed by name (as they
   would if the program was accessing files by relative path in the current working
   directory).
 * The Veracruz 'virtual filesystem' layer does not support directories (other than
   the current one), querying or changing file permissions, attributes, etc, or
   polling for changes.
 * File-likes can't be renamed, and can only be accessed in the manner set by global
   policy (e.g. inputs can only be opened for reading). FDs can't be renumbered.
 * CLI args, environment variables, sockets, symlinks, and clocks/timers are unsupported.
 * Files and rights (WASI term of capabilities) are set by global policy.

## WASI Implementation Summary

A summary our WASI implementation. We repeat the high-level WASI API definitions in [wasi_snapshot_preview1][1] 
and the actual ABI definitions in [here][2], and provide our understanding of the WASI ABI standard and implementation strategy.
Any WASI ABI that veracruz currently does not support, labeled with **NOT SUPPORTED** through this document,
will return `ErrNo::NoSys` _after_ right (capability) check and minimum validity check on parameters.

### Args and Env

We implement argument and environment WASI ABI for the program yet they are _NOT_ tested.
Also, there is _NO_ API for participants to access the arguments and environment variables.

#### `args_get`
```rust
fn args_get(argv: Pointer<Pointer<u8>>, argv_buf: Pointer<u8>) -> Result<(),ErrNo>;
fn args_get(argv: u32, argv_buf: u32) -> ErrNo;
```
Return the arguments. Each argument is `\0`-ended. All arguments are stored at the memory 
at `argv_buf`. `argv` stores addresses (pointing to `argv_buf`) to arguments.
For example:
```
             ----------------------------------
argv_buf --> |  ... \0 ... \0 ... \0 ... ...
             ----------------------------------
             ^         ^      ^      ^
         ----------------------------------
argv --> |  0x12  |  0x34  |  0x56 | ..
         ----------------------------------
``` 
**Question:** Not sure the upper bound of `argv` and `argv_buf`.

#### `args_sizes_get`
```rust
fn args_sizes_get() -> Result<(size, size), ErrNo>;
fn args_sizes_get(argc: u32, argv_buf_size: u32) -> ErrNo;
``` 
Write the number of arguments to the memory at `argc`, 
and the total number of valid bytes of `argv_buf` (in `args_get`), including `\0`, to the memory at `argv_buf_size`.

#### `environ_get`
```rust 
fn environ_get(environ: Pointer<Pointer<u8>>, environ_buf: Pointer<u8>) -> Result<(), ErrNo>;
fn environ_get(environ: u32, environ_buf: u32) -> ErrNo;
```
Return the environment variables in a similar style as `args_get`, 
however, each entry is of the form `$KEY=$VALUE`.
For example:
```
                ------------------------------------------
environ_buf --> |  key1=value1 \0 key2=value \0 ...  ...
                ------------------------------------------
                   ^              ^             ^      ^
              ---------------------------------------------
environ -->   |  0x12         |  0x34        |  0x56 | ..
              ---------------------------------------------
``` 
**Question:** Not sure the upper bound of `environ_buf` and `environ`.

#### `environ_sizes_get`
```rust
fn environ_sizes_get() -> Result<(size, size), ErrNo>;
fn environ_sizes_get(environ_count, environ_buf_size) -> ErrNo;
```
Write the number of environment variables to the memory at `environ_count`, 
and the total number of valid bytes of `environ_buf` (in `environ_get`), including `\0`, 
to the memory at `environ_buf_size`.

### Times

Veracruz does not support any time API for now.

#### `clock_res_get`
```rust
fn clock_res_get(id: ClockId) -> Result<Timestamp, ErrNo>;
fn clock_res_get(id: u32, resolution: u32) -> ErrNo;
```
Write the time resolution as `u64` to the memory at `resolution`. 

**NOT SUPPORTED**

#### `clock_res_get`
```rust
fn clock_time_get(id: ClockId, precision: Timestamp) -> Result<Timestamp, ErrNo>;
fn clock_time_get(id: u32, precision: u64, time: u32) -> ErrNo;
```
Write the time of `precision` to the memory at `time`. 

**NOT SUPPORTED**

### Files

Veracruz implements a minimum VFS for supporting basic read from and write to files.
It has no directory structure and all files are stored at `$ROOT`, i.e. path `/`.
We only tested the following calls:
* `fd_close`
* `fd_prestat_get`
* `fd_prestat_dir_name`
* `fd_read`
* `fd_pread`
* `fd_write`
* `fd_pwrite`
* `fd_seek`
* `fd_tell`
* `path_open`

The test source programs can be found at `$VARCRUZ_ROOT/sdk/rust-examples`.

#### `fd_advise`
```rust
fn fd_advise(fd: Fd, offset: FileSize, len: FileSize, advice: Advice) -> Result<(),ErrNo>;
fn fd_advise(fd: u32, offset: u64, len: u64, advice: u8) -> ErrNo;
```
Set the access advice of the file descriptor `fd` at `offset` of the length `len` to be `advice`.
WASM passes a `u32` as the `advice` parameter.
Veracruz only stores advice information without using it.

#### `fd_allocate`
```rust
fn fd_allocate(fd: Fd, offset: FileSize, len: FileSize) -> Result<(),ErrNo>;
fn fd_allocate(fd: u32, offset: u64, len: u64) -> Result<(),ErrNo>;
```
Pre-allocate space for the file descriptor `fd` at `offset` of the length `len`.

**NOT SUPPORTED**

#### `fd_close`
```rust
fn fd_close(fd: Fd) -> Result<(), ErrNo>;
fn fd_close(fd: u32) -> ErrNo;
```
Close the file descriptor `fd`.

#### `fd_datasync`
```rust
fn fd_datasync(fd: Fd) -> Result<(), ErrNo>;
fn fd_datasync(fd: u32) -> ErrNo;
```
**NOT SUPPORTED**

#### `fd_fdstat_get`
```rust
fn fd_fdstat_get(fd: Fd) -> Result<FdStat, ErrNo>;
fn fd_fdstat_get(fd: u32, fd_stat: u32) -> ErrNo;
```
Write the status of the file descriptor `fd` to the memory at `fd_stat`.

#### `fd_fdstat_set_flags`
```rust
fn fd_fdstat_set_flags(fd: Fd, flags: FdFlags) -> Result<(), ErrNo>;
fn fd_fdstat_set_flags(fd: u32, flags: u16) -> ErrNo;
```
Set the flags of the file descriptor `fd` to `flags`.
WASM passes a `u32` as the `flag` parameter.

#### `fd_fdstat_set_rights`
```rust
fn fd_fdstat_set_rights(fd: Fd, base: Rights, inheriting: Rights) -> Result<(), ErrNo>;
fn fd_fdstat_set_rights(fd: u32, base: u64, inheriting: u64) -> ErrNo;
```
Set the base rights and inheriting rights of the file descriptor `fd` to `base` and `inheriting` respectively.

#### `fd_filestat_get`
```rust
fn fd_filestat_get(fd: Fd) -> Result<FileStat, ErrNo>;
fn fd_filestat_get(fd: u32, file_stat: u32) -> ErrNo;
```
Write the status of the file opened by the file descriptor `fd` to the memory at `fd_stat`.

#### `fd_filestat_set_size`
```rust
fn fd_filestat_set_size(fd: Fd, size: FileSize) -> Result<(), ErrNo>;
fn fd_filestat_set_size(fd: u32, size: u64) -> ErrNo;
```
Set the file size of the file opened by the file descriptor `fd` to the new size `size`. 
It will zero-fill, if the new size is larger than the existing size,
or truncate, if the new size is smaller.

#### `fd_filestat_set_times`
```rust
fn fd_filestat_set_times(fd: Fd, atime: Timestamp, mtime: Timestamp, flags: SetTimeFlags) -> Result<(), ErrNo>;
fn fd_filestat_set_times(fd: u32, atime: u64, mtime: u64, flags: u16) -> ErrNo;
```
Set the time(s) of the file opened by the file descriptor `fd` based on the `flags`:
* If `ATIME_NOW` is set, set the last access time to the current time.
* If `ATIME` is set, set the last access time to `atime`.
* If `MTIME_NOW` is set, set the last modification time to the current time.
* If `MTIME` is set, set the last modification time to `mtime`.

Veracruz immediately returns `NoSys` if `ATIME_NOW` or `MTIME_NOW` is set.
Veracruz internally does _NOT_ update the time information and also never use them.
WASM passes a `u32` as the `flags` parameter.

**QUESTION:** Priority of the flags.

#### `fd_prestat_get`
```rust
fn fd_prestat_get(fd: Fd) -> Result<Prestat, ErrNo>;
fn fd_prestat_get(fd: u32, pre_stat: u32) -> ErrNo;
```
Write the status of the pre-opened file descriptor `fd` to the memory at `pre_stat`. If the file descriptor is not pre-opened, return `BadF`.

#### `fd_prestat_dir_name`
```rust
fn fd_prestat_dir_name(fd: Fd, path: Pointer<u8>, len: size) -> Result<(), ErrNo>;
fn fd_prestat_dir_name(fd: u32, path: u32, len: u32) -> ErrNo;
```
Write the pre-opened path opened by the file descriptor `fd` to the memory address at `path`.
The path length must not exceed `len`.

#### `fd_readdir`
```rust
fn fd_readdir(fd: fd, buf: Pointer<u8>, len: size, cookie: DirCookie) -> Result<Size, ErrNo>;
fn fd_readdir(fd: u32, buf: u32, len: u32, size: u32) -> ErrNo;
```
Write the directory entries, consisting of meta-data of type `DirEnt` and the path name as a string, to the memory at `buf` in sequence.
The path name, particularly the length, must be consistent with the metadata.
Write the actual number of written bytes to the memory at `size`, which must not exceed `len`.
For example,

```
        v  ... ... ... ...        len      ... ... ... ...    v
        -------------------------------------------------------
buf --> |  dirent[0] path[0] dirent[1] path[1] ... ... ... ...|
        -------------------------------------------------------
        ^  ... ... ...       size         ... ... ...  ^
```

**NOT SUPPORTED**

#### `fd_renumber`
```
fn fd_renumber(fd: Fd, to: Fd) -> Result<(), ErrNo>;
fn fd_renumber(fd: u32, to: u32) -> ErrNo;
```
Re-number the file descriptor `fd` to `to`, under the conditions:
* `fd` is a valid file descriptor, and
* `to` is free.

If any condition is unsatisfied, return `BadF`.

#### `fd_read`
```
fn fd_read(fd: Fd, iovs: Pointer<IoVec>) -> Result<Size, ErrNo>;
fn fd_read(fd: u32, iovs_base: u32, iovs_len: u32, size: u32) -> ErrNo;
```
Read from the current offset of the file descriptor `fd` and move the offset accordingly. Refer to `fd_pread` and `fd_seek` for more details.

#### `fd_pread`
```
fn fd_pread(fd: Fd, iovs: Pointer<IoVec>, offset: FileSize) -> Result<Size, ErrNo>;
fn fd_pread(fd: u32, iovs_base: u32, iovs_len: u32, offset: u64, size: u32) -> ErrNo;
```
Read from the file descriptor `fd` without accessing the internal offset but using the offset parameter `offset`. The read bytes are stored into the buffer(s) indexed by `iovs_base` in sequence.
Specifically, `iovs_base` points to an array of `iovs_len` numbers of `IoVec` metadata,
consisting of a pointer and a length to a buffer.
For example:
```
          --------------------------------------------------------
iovs -->  |  iovs[0]  iovs[1] ... ... ... ... iovs[iovs_len - 1] |
          --------------------------------------------------------
point to:     v          v                             v
          ----------  -------  ... ... ... ...  ---------------
          | aaaaa  |  | bbb |  ... ... ... ...  | (untouched) |
          ----------  -------  ... ... ... ...  ---------------
read from:    ^          ^       ^       ^
          --------------------------------------------------------
offset -> |  aaaaa  |  bbb   |  ...  |  ...  | .. (EOF)
          --------------------------------------------------------
size  =       5     +   3    +  ...  +  ...  + ..
```
Last, write the actual number of read bytes to the memory at `size`.

#### `fd_write`
```
fn fd_write(fd: Fd, iovs: ConstPointer<IoVec>) -> Result<Size, ErrNo>;
fn fd_write(fd: u32, iovs_base: u32, iovs_len: u32, size: u32) -> ErrNo;
```
Write to the current offset of the file descriptor `fd` and move the offset accordingly. Refer to `fd_pwrite` and `fd_seek` for more details.

#### `fd_pwrite`
```
fn fd_pwrite(fd: Fd, iovs: ConstPointer<IoVec>, offset: FileSize) -> Result<Size, ErrNo>;
fn fd_pwrite(fd: u32, iovs_base: u32, iovs_len: u32, offset: u64, size: u32) -> ErrNo;
```
Write to the file descriptor `fd` without accessing the internal offset but using the offset parameter `offset`. The written bytes are from the buffers indexed by `iovs_base` in sequence.
Specifically, `iovs_base` points to an array of `iovs_len` numbers of `IoVec` metadata,
consisting of a pointer and a length to a buffer.
For example:
```
          --------------------------------------------------------
iovs -->  |  iovs[0]  iovs[1] ... ... ... ... iovs[iovs_len - 1] |
          --------------------------------------------------------
point to:     v          v                             v
          ----------  -------  ... ... ... ...  ---------------
          | aaaaa  |  | bbb |  ... ... ... ...  | (untouched) |
          ----------  -------  ... ... ... ...  ---------------
write to:     v          v       v       v
          --------------------------------------------------------
offset -> | aaaaa   |  bbb   |  ...  |  ...  | .. (out of space)
          --------------------------------------------------------
size  =       5     +   3    +  ...  +  ...  + ..
```
Last, write the actual number of written bytes to the memory at `size`.

#### `fd_seek`
```rust
fn fd_seek(fd: Fd, delta: FileDelta, whence: Whence) -> Result<FileSize, ErrNo>;
fn fd_seek(fd: u32, delta: i64, whence: u8, offset: u32) -> ErrNo;
```
Move the offset of the file descriptor `fd` based on the flag `whence`:
* if it is `Current`, move from the current offset by `delta`;
* if it is `Start`, move from the start of the file by `delta`; or 
* if it is `End`, move from the end of the file by `delta`.
If the new offset is negative or exceeds the file size, return `SPipe` (invalid seek).
Otherwise, write the new offset to the memory at `offset`.

#### `fd_sync`
```rust
fn fd_sync(fd: Fd) -> Result<(), ErrNo>;
fn fd_sync(fd: u32) -> ErrNo;
```

**NOT SUPPORTED**

#### `fd_tell`
```rust
fn fd_tell(fd: Fd) -> Result<FileSize, ErrNo>;
fn fd_tell(fd: u32, offset: u32) -> ErrNo;
```
Write the offset of the file descriptor `fd` to the memory at `offset`.

#### `path_create_directory` 
```rust
fn path_create_directory(fd: Fd, path: String) -> Result<(), ErrNo>;
fn path_create_directory(fd: Fd, path_addr: u32, path_len: u32) -> Result<(), ErrNo>;
```
Read the new directory path at address `path_addr` of length `path_len`.
Then create a new directory starting from the directory opened by the file descriptor `fd`.

**NOT SUPPORTED**

#### `path_remove_directory`
```rust
fn path_remove_directory(fd: Fd, path: String) -> Result<(), ErrNo>;
fn path_remove_directory(fd: Fd, path_addr: u32, path_len: u32) -> Result<(), ErrNo>;
```
Read the path at address `path_addr` of length `path_len`.
Then remove the directory starting from the directory opened by the file descriptor `fd`.

**NOT SUPPORTED**

#### `path_filestat_get`
```rust
fn path_filestat_get(fd: Fd, flags: LookupFlags, path: String) -> Result<FileStat, ErrNo>;
fn path_filestat_get(fd: u32, flags: u32, path_addr: u32, path_len: u32, file_stat: u32) -> ErrNo;
```
Read the path at address `path_addr` of length `path_len`.
Then write the status of the file at the path starting from the directory opened by the file descriptor `fd`. 

**NOT SUPPORTED**
#### `path_filestat_set_times`
```
fn path_filestat_set_times(fd: Fd, lookup_flags: LookupFlags, path: String, atime: Timestamp, mtime: Timestamp, fst_flags: SetTimeFlags) -> Result<(), ErrNo>;
fn path_filestat_set_times(fd: u32, lookup_flags: u32, path_addr: u32, path_len: u32, atime: u64, mtime: u64, fst_flags: u16) -> ErrNo;
```
Read the path at address `path_addr` of length `path_len`.
Set the time(s) of the file at the path starting from the descriptor opened by the file descriptor `fd` based on the `fst_flags`:
* If `ATIME_NOW` is set, set the last access time to the current time.
* If `ATIME` is set, set the last access time to `atime`.
* If `MTIME_NOW` is set, set the last modification time to the current time.
* If `MTIME` is set, set the last modification time to `mtime`.

We ignore the lookup flags `lookup_flags` and only support `fd` being the `ROOT`.
Veracruz internally does _NOT_ update the time information and also never use them.
WASM passes a `u32` as the `flags` parameter.

**QUESTION:** Priority of the flags.

#### `path_link`
```rust
fn path_link(old_fd: Fd, old_flags: LookupFlags, old_path: String, new_fd: Fd, new_path: String) -> Result<(),ErrNo>;
fn path_link(old_fd: u32, old_flags: u32, old_path_addr: u32, old_path_len: u32, new_fd: u32, new_path_addr: u32, new_path_len: u32) -> ErrNo;
```

**NOT SUPPORTED**

#### `path_open`
```rust
fn path_open(fd: Fd, dirflags: LookupFlags, path: String, oflags: OpenFlags, base: Rights, inheriting: Rights, fdflags: FdFlags) -> Result<Fd, ErrNo>;
fn path_open(fd: u32, dirflags: u32, path_addr: u32, path_len: u32, oflags: u16, base: u64, inheriting: u64, fdflags: u16, new_fd: u32) -> ErrNo;
```
Read the path at address `path_addr` of length `path_len`.
The behaviour of `path_open` varies based on the open flags `oflags`:
* if no flag is set, open a file at the path, if exists, starting from the directory opened by the file descriptor `fd`;
* if `EXCL` is set, `path_open` fails if the path exists;
* if `CREATE` is set, create a new file at the path if the path does not exist;
* if `TRUNC` is set, the file at the path is truncated, that is, clean the content and set the file size to ZERO; and
* if `DIRECTORY` is set, `path_open` fails if the path is not a directory.

The base rights and inheriting rights the new fd `new_fd` cannot exceed `base` and `inheriting`, respectively.
Veracruz internally use an extra `principal` parameter to restrict the rights.
The status of the new fd `new_fd` are set to be `fdflags`.
Last, write the new file descriptor to the memory at `new_fd`.
We ignore the lookup flags `lookup_flags` and only support `fd` being the `ROOT`.
Veracruz does _NOT_ support `DIRECTORY` flag.
WASM passes `u32` as the `oflags` and `fdflags` parameters.

**QUESTION:** Priority of the flags.

#### `path_readlink`
```rust
fn path_readlink(fd: Fd, path: String, buf: Pointer<u8>, buf_len: size) -> Result<Size, ErrNo>;
fn path_readlink(fd: u32, path_addr: u32, path_len: u32, buf: u32, buf_len: u32, size: u32) -> ErrNo;
```
**NOT SUPPORTED**

#### `path_rename`
```rust
fn path_rename(fd: Fd, old_path: String, new_fd: Fd, new_path: String) -> Result<(), ErrNo>;
fn path_rename(fd: u32, old_path_addr: u32, old_path_len: u32, new_fd: u32, new_path_addr: u32, new_path_len: u32) -> ErrNo;
```

**NOT SUPPORTED**

#### `path_symlink`
```rust
fn path_symlink(old_path: String, fd: Fd, new_path: String) -> Result<(), ErrNo>;
fn path_symlink(old_path_addr: u32, old_path_len: u32, fd: u32, new_path_addr: u32, new_path_len: u32) -> ErrNo;
```

**NOT SUPPORTED**

#### `path_unlink_file`
```rust
fn path_unlink_file(fd: Fd, path: String) -> Result<(), ErrNo>;
fn path_unlink_file(fd: u32, path_addr: u32, path_len: u32) -> ErrNo;
```

**NOT SUPPORTED**

### Scheduling and Signals

#### `poll_oneoff`
```rust
fn poll_oneoff(in: ConstPointer<Subscription>, out: Pointer<Event>, nsubscriptions: Size) -> Result<Size, ErrNo>;
fn poll_oneoff(in: u32, out: u32, nsubscriptions: u32, size: u32) -> ErrNo;
```

**NOT SUPPORTED**

#### `proc_exit`
```rust
fn proc_exit(error: Exitcode) -> !;
fn proc_exit(error: u32) -> !;
```
Terminate the execution with error code `error`. 
We cannot find API for terminating execution in in WASMI and wasmtime.
Hence Veracruz stores the `error` and allows to execute further, which is likely to raise a trap due to an `Unreachable` command immediately after `proc_exit`.

#### `proc_raise`
```rust
fn proc_raise(sig: Signal) -> Result<(), ErrNo>;
fn proc_raise(sig: u8) -> ErrNo;
```
WASM passes a `u32` as the `sig` parameter.

**NOT SUPPORTED**

#### `sched_yield`
```rust
fn sched_yield() -> Result<(), ErrNo>;
fn sched_yield() -> ErrNo;
```

**NOT SUPPORTED**

### Randomness

#### `random_get`
```rust
fn random_get(buf: Pointer<u8>, buf_len: size) -> Result<(), ErrNo>;
fn random_get(buf: u32, buf_len: u32) -> ErrNo;
```
Fill in `buf_len` of random bytes to the memory at the address `buf`.

### Sockets

#### `sock_recv`
```rust
fn sock_recv(socket: Fd, ri_data: Pointer<IoVec>, ri_flags: RiFlags) -> Result<(Size, RoFlags), ErrNo>;
fn sock_recv(socket: u32, ri_data_addr: u32, ri_data_len: u32, ri_flags: u16, size: u32, ro_flags: u32) -> ErrNo;
```
WASM passes a `u32` as the `ri_flags` parameter.

**NOT SUPPORTED**

#### `sock_send`
```rust
fn sock_send(socket: Fd, si_data: ConstPointer<IoVec>, si_flags: SiFlags) -> Result<Size, ErrNo>;
fn sock_send(socket: u32, si_data_addr: u32, si_data_len: u32, si_flags: u16, size: u32) -> ErrNo;
```
WASM passes a `u32` as the `si_flags` parameter.

**NOT SUPPORTED**

#### `sock_shutdown` 
```rust
fn sock_shutdown(socket: Fd, flags: SdFlags) -> Result<(), ErrNo>;
fn sock_shutdown(socket: u32, flags: u8) -> ErrNo;
```
WASM passes a `u32` as the `flags` parameter.

**NOT SUPPORTED**

## Some Possible Future Directions

 * Test suite for WASI ABI.
 * More WASI functionality: 
    - Add the support for directories. 
    - Separate file descriptor spaces for different principals, 
      e.g. participants and programs. Pre-opened file descriptors in each 
      space have the rights match the policy file.
 * Event-oriented models: WASI poll could be implemented to allow Veracruz
   programs to wait for events.
 * Streaming, producer/consumer and multi-program graphs: file-like objects
   behaving like named pipes would enable lots of more complex usage models,
   especially if combined with poll support. In the simplest streaming case,
   the program would simply read from the streaming input, with the runtime
   blocking the read hcall until enough bytes are available. In a more
   complex case, there might be multiple programs running, with named pipes
   for communication between them, and a program might use poll (or similar)
   to multiplex events when listening on multiple pipes. Alternatively,
   sockets could be introduced, and send/recv semantics could be used.
 * Introspective and reactive programs: supporting some of the fd metadata APIs
   in WASI might enable programs to dynamically adapt their behaviour to their
   environment, simple example: optionally producing a second output (debug log)
   that can be enabled in policy without any program change. If we want to add
   information flow control labels, and we want to allow programs to see or
   manipulate those labels, metadata APIs might be a path forward (with
   appropriate library support).

[1]: https://github.com/WebAssembly/WASI/blob/master/phases/snapshot/docs.md#-wasi_snapshot_preview1
[2]: https://github.com/bytecodealliance/wasi/blob/main/src/lib_generated.rs
