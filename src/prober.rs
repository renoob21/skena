use std::{io::{BufRead, BufReader, Read, Write}, net::{IpAddr, SocketAddr, TcpStream}, time::Duration};

use regex::Regex;

use crate::scanner::ScanResult;

const READ_WRITE_TIMEOUT_MS: u64 = 500;

pub trait Prober {
    fn service_name(&self) -> &str;
    fn default_ports(&self) -> &[u16];
    fn probe(&self, ip: IpAddr, port: u16) -> ScanResult;
}

pub struct ServiceProbe {
    name: String,
    ports: Vec<u16>,
    payload: Option<String>,
    match_regex: String,
}

impl Prober for ServiceProbe {
    fn service_name(&self) -> &str {
        &self.name
    }

    fn default_ports(&self) -> &[u16] {
        &self.ports
    }

    fn probe(&self, ip: IpAddr, port: u16) -> ScanResult {
        let addr = SocketAddr::new(ip, port);

        if let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_secs(1)) {
            stream.set_read_timeout(Some(Duration::from_millis(READ_WRITE_TIMEOUT_MS))).unwrap();
            stream.set_write_timeout(Some(Duration::from_millis(READ_WRITE_TIMEOUT_MS))).unwrap();

            if let Some(load) = &self.payload {
                if let Err(_) = stream.write_all(load.as_bytes()) {
                    return ScanResult::TcpOpen(port, None);
                }
            }

            let re = Regex::new(&self.match_regex).unwrap();

            let buf_reader = BufReader::new(&stream);

            let banner: String = buf_reader.lines()
                    .map(|line| line.unwrap_or("".to_string()))
                    .take_while(|line| re.captures(&line).is_some())
                    .collect();
            

            ScanResult::TcpOpen(port, Some(banner))
        } else {
            ScanResult::Closed
        }
    }
}