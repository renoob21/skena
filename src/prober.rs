use std::{collections::HashMap, net::{IpAddr, SocketAddr}, time::Duration, fs};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream, time::timeout};
use async_trait::async_trait;

use regex::Regex;
use toml::{Table, Value};

use crate::scanner::{ScanResult, CONNECTION_TIMEOUT_MS};

#[async_trait]
pub trait Prober: Send + Sync {
    fn service_name(&self) -> &str;
    fn default_ports(&self) -> &[u16];
    async fn probe(&self, ip: IpAddr, port: u16) -> ScanResult;
}

#[derive(Debug)]
pub struct GenericServiceProbe {
    name: String,
    ports: Vec<u16>,
    payload: Option<String>,
    match_regex: String,
}

#[async_trait]
impl Prober for GenericServiceProbe {
    fn service_name(&self) -> &str {
        &self.name
    }

    fn default_ports(&self) -> &[u16] {
        &self.ports
    }

    async fn probe(&self, ip: IpAddr, port: u16) -> ScanResult {
        let addr = SocketAddr::new(ip, port);

        let connect_attempt = TcpStream::connect(addr);

        if let Ok(Ok(mut stream)) = timeout(Duration::from_millis(CONNECTION_TIMEOUT_MS), connect_attempt).await {
            if let Some(load) = &self.payload {
                if load.len() > 0 {
                    if let Err(_) = stream.write_all(load.as_bytes()).await {
                        return ScanResult::TcpOpen(port, None);
                    };
                }
            };

            let re = Regex::new(&self.match_regex).unwrap();

            let mut buffer = Vec::new();

            let banner = match stream.read_to_end(&mut buffer).await {
                Ok(_) => {
                    let captured_str = String::from_utf8_lossy(&buffer).into_owned();

                    let mut new_str = String::new();

                    for cap in re.captures_iter(&captured_str) {
                        new_str.push_str(&cap[0]);
                    }

                    Some(new_str)
                }
                Err(_) => None
            };
            ScanResult::TcpOpen(port, banner)
            } else {
            ScanResult::Closed
        }
    }
}

pub struct ProbeRegistry {
    pub port_map: HashMap<u16, Vec<usize>>,
    // fallback_probes: Vec<&'a dyn Prober + Send + Sync>,
    pub owned_probes: Vec<Box<dyn Prober + Send + Sync>>,
}

impl ProbeRegistry {
    pub fn new() -> Result<Self, String> {
        let probe_file = match fs::read_to_string("probes.toml") {
            Ok(file) => file,
            Err(_) => return Err(String::from("Cannot read probe registry file"))
        };

        let toml_probes = match probe_file.parse::<Table>() {
            Ok(table) => table,
            Err(_) => return Err(String::from("Cannot read probe registry file"))
        };

        let mut owned_probes: Vec<Box<dyn Prober + Send + Sync>> = Vec::new();
        let mut port_map: HashMap<u16, Vec<usize>> = HashMap::new();

        match toml_probes["probe"].clone() {
            Value::Array(arr) => {
                for val in arr {
                    let name = val["name"].as_str().unwrap();
                    let payload = match val["payload"].as_str() {
                        Some(load) => Some(load.to_string()),
                        None => None
                    };
                    let ports: Vec<u16> = val["ports"].as_array().unwrap().iter().map(|val| val.as_integer().unwrap() as u16).collect();
                    let match_regex = val["match_regex"].as_str().unwrap();

                    

                    let probe_box = Box::new(
                        GenericServiceProbe {
                            name: name.to_string(),
                            payload,
                            ports: ports.clone(),
                            match_regex: match_regex.to_string(),
                        }
                    );

                    owned_probes.push(probe_box);

                    for port in ports {
                        port_map.entry(port).or_default().push(owned_probes.len() - 1);
                    }
                    
                }
            },
            _ => return Err(String::from("Cannot read probe registry file"))
        }
        
        
        

        Ok(ProbeRegistry { port_map, owned_probes: owned_probes })

    }

    
}