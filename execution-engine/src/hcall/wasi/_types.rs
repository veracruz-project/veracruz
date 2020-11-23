//! Associated WASI types and common definitions.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

pub type Size = u32;

pub type FileSize = u64;

pub type TimeStamp = u64;

pub enum ClockID {
    Realtime,
    Monotonic,
    ProcessCPUTimeID,
    ThreadCPUTimeID
}

pub enum ErrNo {
    Success,
    TooBig,
    Access,
    AddressInUse,
    AddressNotAvailable,
    AddressFamilyNotSupported,
    Again,
    Already,
    BadFileDescriptor,
    BadMessage,
    Busy,
    Canceled,
    Child,
    ConnectionAborted,
    ConnectionRefused,
    ConnectionReset,
    Deadlock,
    DestinationAddressRequired,
    Domain,
    DQuot,
    Exists,
    Fault,
    FileTooBig,
    HostUnreachable,
    IdentifierRemoved,
    IllegalSequence,
    InProgress,
    Interrupted,
    Invalid,
    IO,
    IsConnected,
    IsDirectory,
    Loop,
    MFile,
    MLink,
    MessageSize,
    Multihop,
    NameTooLong,
    NetDown,
    NetReset,
    NetUnreachable,
    NFile,
    NoBuffers,
    NoDevice,
    NoEntity,
    NoExecutable,
    NoLock,
    NoLink,
    NoMemory,
    NoMessage,
    NoProtocol,
    NoSpace,
    NoSystem,
    NotConnected,
    NotDirectory,
    NotEmpty,
    NotRecoverable,
    NotSocket,
    NotSupported,
    NoTTY,
    NXIO,
    Overflow,
    OwnerDead,
    Permissions,
    Pipe,
    ProtocolError,
    ProtocolNotSupported,
    ProtocolType,
    Range,
    ReadOnlyFS,
    SPipe,
    Search,
    Stale,
    TimedOut,
    TextBusy,
    XDevice,
    NotCapable
}

pub enum Rights {
    FDDataSync,
    FDRead,
    FDSeek,
    FDFDStateSetFlags,
    FDSync,
    FDTell,
    FDWrite,
    FDAdvise,
    FDAllocate,
    PathCreateDirectory,
    PathCreateFile,
    PathLinkSource,
    PathLinkTarget,
    PathOpen,
    FDReadDir,
    PathReadLink,
    PathRenameSource,
    PathRenameTarget,
    PathFileStatGet,
    PathFileStatSetSize,
    PathFileStatSetTimes,
    PathSymlink,
    PathRemoveDirectory,
    PathUnlinkFile,
    PollFDReadWrite,
    SockShutdown
}

pub type FD = u32;

pub struct IOVec {
    buf: Pointer<u8>,
    buf_len: Size
}