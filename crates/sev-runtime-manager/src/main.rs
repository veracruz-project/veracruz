//! The Runtime Manager for AMD-SEV
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use anyhow::Result;

use nix::{
    mount::{
        mount,
        MsFlags,
    },
    sys::{
        socket::{
            accept, bind, listen as listen_vsock, socket, AddressFamily, SockAddr, SockFlag, SockType,
        },
        stat::Mode,
    },
    unistd::mkdir,
};
use raw_fd::{receive_buffer, send_buffer};

use runtime_manager::common_runtime::CommonRuntime;

pub mod sev_runtime;

/// The CID for the VSOCK to listen on
/// Currently set to all 1's so it will listen on all of them
const CID: u32 = 0xFFFFFFFF; // VMADDR_CID_ANY
/// The incoming port to listen on
const PORT: u32 = 5005;
/// max number of outstanding connections in the socket listen queue
const BACKLOG: usize = 128;

fn init() {
    // These cannot currently be constants
    let chmod_0555: Mode = Mode::S_IRUSR
        | Mode::S_IXUSR
        | Mode::S_IRGRP
        | Mode::S_IXGRP
        | Mode::S_IROTH
        | Mode::S_IXOTH;
    let chmod_0755: Mode =
        Mode::S_IRWXU | Mode::S_IRGRP | Mode::S_IXGRP | Mode::S_IROTH | Mode::S_IXOTH;
    let common_mnt_flags: MsFlags = MsFlags::MS_NODEV | MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID;

    // /dev/urandom is required very early
    mkdir("/dev", chmod_0755).ok();
    let devtmpfs = Some("devtmpfs");
    mount(
        devtmpfs,
        "/dev",
        devtmpfs,
        MsFlags::MS_NOSUID,
        Some("mode=0755"),
    ).unwrap();

    // Initialize logging
    //env_logger::builder().parse_filters(filters).init();

    // Log retroactively :)
    println!("Starting init");
    println!("Mounting /dev");

    println!("Mounting /proc");
    mkdir("/proc", chmod_0555).ok();
    mount::<_, _, _, [u8]>(Some("proc"), "/proc", Some("proc"), common_mnt_flags, None).unwrap();
}

fn main() -> Result<(), String> {
    encap().map_err(|err| format!("SEV-SNP Runtime Manager::main encap returned error:{:?}", err))
}

fn encap() -> Result<()> {
    init();
    let socket_fd = socket(
        AddressFamily::Vsock,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )?;
    println!("AMD SEV Runtime Manager::main creating SockAddr, CID{:?}, PORT:{:?}", CID, PORT);
    let sockaddr = SockAddr::new_vsock(CID, PORT);

    println!("AMD SEV Runtime Manager::main calling bind");
    bind(socket_fd, &sockaddr)?;

    println!("AMD SEV Runtime Manager::main calling listen_vsock");
    listen_vsock(socket_fd, BACKLOG)?;

    let sev_runtime = sev_runtime::SevRuntime{};

    let runtime = CommonRuntime::new(&sev_runtime);

    loop {
        println!("AMD SEV Runtime Manager::main calling accept");
        let fd = accept(socket_fd)?;
        println!("AMD SEV Runtime Manager::main accept succeeded. Looping");
        loop {
            let received_buffer = receive_buffer(fd)?;
            let response_buffer = runtime.decode_dispatch(&received_buffer)?;
            send_buffer(fd, &response_buffer)?;
        }
    }
}