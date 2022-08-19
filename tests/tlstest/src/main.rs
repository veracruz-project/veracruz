//! Stand-alone test of TLS connection using mbedtls crate
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory
//! for information on licensing and copyright.

use mbedtls::{
    self,
    alloc::List,
    pk::Pk,
    ssl::{ciphersuites, config, Config, Context},
    x509::Certificate,
};
use std::{cell::Cell, io::Read, io::Write, sync::Arc, sync::Mutex, vec::Vec};

fn dump_hex(desc: &str, data: &[u8]) {
    let mut i = 0;
    while i < data.len() {
        let mut s: String = desc.to_string();
        let m = std::cmp::min(data.len(), i + 16);
        let mut j = i;
        while j < m {
            s += &format!("{:02x}", data[j]);
            j += 1;
            if j < m {
                s += " ";
            }
        }
        println!("{}", s);
        i += 16;
    }
}

fn read_all_bytes_in_file(filename: &str) -> Vec<u8> {
    let mut file = match std::fs::File::open(filename) {
        Ok(x) => x,
        _ => panic!("Cannot open {}", &filename),
    };
    let mut buffer = std::vec::Vec::new();
    file.read_to_end(&mut buffer).unwrap();
    buffer
}

fn read_certs(filename: &str) -> List<Certificate> {
    let mut buffer = read_all_bytes_in_file(filename);
    buffer.push(b'\0');
    Certificate::from_pem_multiple(&buffer).unwrap()
}

fn read_private_key(filename: &str) -> Pk {
    let mut buffer = read_all_bytes_in_file(filename);
    buffer.push(b'\0');
    Pk::from_private_key(
        &mut mbedtls::rng::CtrDrbg::new(Arc::new(mbedtls::rng::OsEntropy::new()), None).unwrap(),
        &buffer,
        None,
    )
    .unwrap()
}

fn client_config() -> Config {
    let mut config = Config::new(
        config::Endpoint::Client,
        config::Transport::Stream,
        config::Preset::Default,
    );
    config.set_min_version(config::Version::Tls1_3).unwrap();
    config.set_max_version(config::Version::Tls1_3).unwrap();
    let ciphersuite_name = "TLS1-3-CHACHA20-POLY1305-SHA256";
    let ciphersuite = ciphersuites::lookup_ciphersuite(&ciphersuite_name).unwrap();
    config.set_ciphersuites(Arc::new(vec![ciphersuite, 0]));
    let entropy = Arc::new(mbedtls::rng::OsEntropy::new());
    let rng = Arc::new(mbedtls::rng::CtrDrbg::new(entropy, None).unwrap());
    config.set_rng(rng);

    config.set_ca_list(Arc::new(read_certs("server-crt.pem")), None);
    config
        .push_cert(
            Arc::new(read_certs("client-crt.pem")),
            Arc::new(read_private_key("client-key.pem")),
        )
        .unwrap();

    config
}

fn server_config() -> Config {
    let mut config = Config::new(
        config::Endpoint::Server,
        config::Transport::Stream,
        config::Preset::Default,
    );
    config.set_min_version(config::Version::Tls1_3).unwrap();
    config.set_max_version(config::Version::Tls1_3).unwrap();
    let ciphersuite_name = "TLS1-3-CHACHA20-POLY1305-SHA256";
    let ciphersuite = ciphersuites::lookup_ciphersuite(&ciphersuite_name).unwrap();
    config.set_ciphersuites(Arc::new(vec![ciphersuite, 0]));
    let entropy = Arc::new(mbedtls::rng::OsEntropy::new());
    let rng = Arc::new(mbedtls::rng::CtrDrbg::new(entropy, None).unwrap());
    config.set_rng(rng);

    config.set_ca_list(Arc::new(read_certs("server-crt.pem")), None);
    config
        .push_cert(
            Arc::new(read_certs("server-crt.pem")),
            Arc::new(read_private_key("server-key.pem")),
        )
        .unwrap();
    config.set_authmode(config::AuthMode::Required);

    config
}

fn checked_read<T: Read>(desc: &str, o: &mut T, data: &[u8]) -> usize {
    let mut buffer = vec![0; data.len()];
    let n = match o.read(&mut buffer) {
        Ok(n) => {
            if n == 0 && data.len() != 0 {
                panic!("bad read: returned EOF");
            }
            n
        }
        Err(err) => {
            if err.kind() != std::io::ErrorKind::WouldBlock {
                panic!("bad read: error {}", err);
            }
            0
        }
    };
    if n > data.len() {
        panic!("bad read: returned n > buf.len()");
    }
    if buffer != data[0..n] {
        panic!("bad read: data did not match with script");
    }
    println!(
        "{} reads plaintext {} bytes ({} to follow)",
        desc,
        n,
        data.len() - n
    );
    n
}

fn checked_write<T: Write>(desc: &str, o: &mut T, data: &[u8]) -> usize {
    let n = match o.write(&data) {
        Ok(n) => {
            if n == 0 && data.len() != 0 {
                panic!("bad write: returned 0");
            }
            n
        }
        Err(err) => {
            if err.kind() != std::io::ErrorKind::WouldBlock {
                panic!("bad write: error {}", err);
            }
            0
        }
    };
    if n > data.len() {
        panic!("bad write: returned n > buf.len()");
    }
    println!("{} writes plaintext {} bytes:", desc, n);
    dump_hex(&format!("{} plaintext : ", &desc), &data[0..n]);
    n
}

struct Connection {
    desc: String,
    recv_buffer: Arc<Mutex<Vec<u8>>>,
    send_buffer: Arc<Mutex<Vec<u8>>>,
    activity: Arc<Mutex<Cell<bool>>>,
}

impl Read for Connection {
    fn read(&mut self, data: &mut [u8]) -> Result<usize, std::io::Error> {
        // Return as much data from the recv_buffer as fits.
        let mut buffer = self.recv_buffer.lock().unwrap();
        let n = std::cmp::min(data.len(), buffer.len());
        if n == 0 {
            Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "Connection Read",
            ))
        } else {
            data[0..n].clone_from_slice(&buffer[0..n]);
            buffer.drain(0..n);
            println!(
                "{} reads cryptotext {} bytes ({} to come)",
                self.desc,
                n,
                buffer.len()
            );
            self.activity.lock().unwrap().set(true);
            Ok(n)
        }
    }
}

impl Write for Connection {
    fn write(&mut self, data: &[u8]) -> Result<usize, std::io::Error> {
        println!("{} writes cryptotext {} bytes:", self.desc, data.len());
        dump_hex(&format!("{} cryptotext : ", &self.desc), &data);
        // Append to send_buffer.
        let mut buffer = self.send_buffer.lock().unwrap();
        buffer.extend_from_slice(data);
        self.activity.lock().unwrap().set(true);
        // Return value to indicate that we handled all the data.
        Ok(data.len())
    }
    fn flush(&mut self) -> Result<(), std::io::Error> {
        Ok(())
    }
}

fn run_script(script: &[&[u8]]) {
    let server_recv_buffer = Arc::new(Mutex::new(Vec::new()));
    let client_recv_buffer = Arc::new(Mutex::new(Vec::new()));
    let activity = Arc::new(Mutex::new(Cell::new(false)));

    let server_connection = Connection {
        desc: "SERVER".to_string(),
        recv_buffer: server_recv_buffer.clone(),
        send_buffer: client_recv_buffer.clone(),
        activity: activity.clone(),
    };
    let client_connection = Connection {
        desc: "CLIENT".to_string(),
        recv_buffer: client_recv_buffer,
        send_buffer: server_recv_buffer,
        activity: activity.clone(),
    };

    let mut server = Context::new(Arc::new(server_config()));
    match server.establish(server_connection, None) {
        Ok(()) => (),
        Err(mbedtls::Error::SslWantRead) => (),
        err => err.unwrap(),
    }

    let mut client = Context::new(Arc::new(client_config()));
    match client.establish(client_connection, None) {
        Ok(()) => (),
        Err(mbedtls::Error::SslWantRead) => (),
        err => err.unwrap(),
    }

    for i in 0..script.len() {
        if script[i].len() == 0 {
            // Nothing.
        } else if i % 2 == 0 {
            // Client sending.
            let mut send_pos = 0;
            let mut recv_pos = 0;
            while recv_pos < script[i].len() {
                activity.lock().unwrap().set(false);
                send_pos += checked_write("CLIENT", &mut client, &script[i][send_pos..]);
                recv_pos += checked_read("SERVER", &mut server, &script[i][recv_pos..send_pos]);
                if !activity.lock().unwrap().get() {
                    panic!("livelock while client sending");
                }
            }
        } else {
            // Server sending.
            let mut send_pos = 0;
            let mut recv_pos = 0;
            while recv_pos < script[i].len() {
                activity.lock().unwrap().set(false);
                send_pos += checked_write("SERVER", &mut server, &script[i][send_pos..]);
                recv_pos += checked_read("CLIENT", &mut client, &script[i][recv_pos..send_pos]);
                if !activity.lock().unwrap().get() {
                    panic!("livelock while server sending");
                }
            }
        }
    }
    println!("FINISHED SCRIPT");
}

fn main() {
    run_script(&[b"abc", b"xyz", b"123"]);
}
