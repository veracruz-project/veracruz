use byteorder::{ByteOrder, LittleEndian};
use nix::sys::socket::listen as listen_vsock;
use nix::sys::socket::{accept, bind, recv, send, MsgFlags, SockAddr};
use nix::sys::socket::{socket, AddressFamily, SockFlag, SockType};
use std::os::unix::io::RawFd;
use veracruz_utils::{ChiapasMessage, NitroStatus};
use lazy_static::lazy_static;
use std::sync::Mutex;

//const CID: u32 = 17;
const CID: u32 = 0xFFFFFFFF; // VMADDR_CID_ANY
const PORT: u32 = 5005;
// Maximum number of outstanding connections in the socket's
// listen queue
const BACKLOG: usize = 128;

lazy_static! {
    static ref MEXICO_CITY_HASH: Mutex<Option<Vec<u8>>> = Mutex::new(None);
}

pub fn send_buffer(fd: RawFd, buffer: &Vec<u8>) -> Result<(), String> {
    println!("Chiapas::send_buffer started with fd:{:?}", fd);
    let len = buffer.len();
    // first, send the length of the buffer
    {
        let mut buf = [0u8; 9];
        LittleEndian::write_u64(&mut buf, buffer.len() as u64);
        let mut sent_bytes = 0;
        println!("Chiapas::send_buffer sending this number of bytes:{:?}", buf.len());
        while sent_bytes < buf.len() {
            sent_bytes += match send(fd, &buf[sent_bytes..buf.len()], MsgFlags::empty()) {
                Ok(size) => size,
                //Err(nix::Error::Sys(EINTR)) =>{
                    //println!("Chiapas::send_buffer as encountered EINTR error");
                    //0
                //},
                Err(err) => {
                    return Err(format!(
                        "SinaloaNitro::send_buffer failed to send bytes of length:{:?}",
                        err
                    ))
                }
            };
            println!("Chiapas::send_buffer has send this number of bytes so far:{:?}",sent_bytes);
        }
    }
    println!("Chiapas::send_buffer has sent the length:{:?}", len);
    // next, send the buffer
    {
        let mut sent_bytes = 0;
        while sent_bytes < len {
            let size = match send(fd, &buffer[sent_bytes..len], MsgFlags::empty()) {
                Ok(size) => size,
                Err(nix::Error::Sys(_)) => 0,
                Err(err) => {
                    return Err(format!(
                        "SinaloaNitro: send_buffer failed to send bytes:{:?}",
                        err
                    ))
                }
            };
            sent_bytes += size;
        }
    }
    println!("Chiapas::send_buffer has completed.");
    return Ok(());
}

fn receive_buffer(fd: RawFd) -> Result<Vec<u8>, String> {
    // first, read the length
    println!("Chiapas::receive_buffer started with fd:{:?}", fd);
    let length = {
        let mut buf = [0u8; 9];
        let len = buf.len();
        let mut received_bytes = 0;
        println!("iterating until we receive len:{:?}", len);
        while received_bytes < len {
            println!("iteration");
            received_bytes += match recv(fd, &mut buf[received_bytes..len], MsgFlags::empty()) {
                Ok(size) => {
                    println!("received:{:?}", size);
                    size
                },
                Err(nix::Error::Sys(EINTR)) => 0,
                Err(err) => {
                    println!("I have experienced an error");
                    return Err(format!(
                        "SinaloaNitro::receive_buffer failed to read bytes of length:{:?}",
                        err
                    ))
                }
            }
        }
        println!("Received num bytes:{:?}", received_bytes);
        println!("Received buffer:{:?}", buf);
        println!("Attempting little endian conversion");
        LittleEndian::read_u64(&buf) as usize
    };
    println!("CHiapas::receive_buffer has read length:{:?}", length);
    let mut buffer: Vec<u8> = vec![0; length];
    // next, read the buffer
    {
        let mut received_bytes: usize = 0;
        while received_bytes < length {
            received_bytes += match recv(fd, &mut buffer[received_bytes..length], MsgFlags::empty())
            {
                Ok(size) => size,
                Err(nix::Error::Sys(EINTR)) => 0,
                Err(err) => {
                    return Err(format!(
                        "SinaloaNitro::receive_buffer failed to read bytes to buffer:{:?}",
                        err
                    ))
                }
            }
        }
    }
    println!("Chiapas::receive_buffer has finished:{:?}", buffer);
    return Ok(buffer);
}

fn get_firmware_version() -> Result<String, String> {
    println!("chiapas::get_firmware_version");
    let version = env!("CARGO_PKG_VERSION");
    return Ok(version.to_string());
}

fn set_mexico_city_hash_hack(hash: Vec<u8>) -> Result<NitroStatus, String> {
    let mut mch_guard = MEXICO_CITY_HASH.lock().map_err(|err| format!("set_mexico_city_hash failed to obtain lock on MEXICO_CITY_HASH:{:?}", err))?;
    *mch_guard = Some(hash);
    Ok(NitroStatus::Success)
}

fn main() -> Result<(), String> {
    let socket_fd = socket(
        AddressFamily::Vsock,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .map_err(|err| format!("Chiapas::main failed to create socket:{:?}", err))?;

    let sockaddr = SockAddr::new_vsock(CID, PORT);

    bind(socket_fd, &sockaddr).map_err(|err| format!("Chiapas::main bind failed:{:?}", err))?;

    listen_vsock(socket_fd, BACKLOG)
        .map_err(|err| format!("Chiapas::main listen_vsock failed:{:?}", err))?;

    let fd =
        accept(socket_fd).map_err(|err| format!("Chiapas::main accept failed:{:?}", err))?;
    loop {
        let received_buffer = receive_buffer(fd)
            .map_err(|err| format!("Chiapas::main receive_buffer failed:{:?}", err))?;
        let received_message: ChiapasMessage = bincode::deserialize(&received_buffer).map_err(|err| format!("Chiapas::main failed to parse received buffer as ChiapasMessage:{:?}", err))?;
        let return_message = match received_message {
            ChiapasMessage::FetchFirmwareVersion => {
                let version = get_firmware_version().map_err(|err| format!("Chiapas::main failed to get version:{:?}", err))?;
                ChiapasMessage::FirmwareVersion(version)
            },
            ChiapasMessage::SetMexicoCityHashHack(hash) => {
                let status = set_mexico_city_hash_hack(hash)?;
                ChiapasMessage::Status(status)
            },
            //ChiapasMessage::NativeAttestation(challenge, device_id) => ,
            _ => return Err(format!("Chiapas::main received unhandled message:{:?}", received_message)),
        };
        let return_buffer = bincode::serialize(&return_message).map_err(|err| format!("Chiapas::main failed to serialize return_message:{:?}", err))?;
        println!("Chiapas::main returning return_buffer:{:?}", return_buffer);
        send_buffer(fd, &return_buffer).map_err(|err| format!("Chiapas::main failed to send return_buffer:{:?}", return_buffer))?;
    }

    Ok(())
}
