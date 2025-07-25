use std::{net::{IpAddr, SocketAddr}, str::FromStr, sync::mpsc, time::Duration};

use tokio::{net::TcpStream, time::timeout};

use crate::{scanner::{ScanResult, Scanner, CONNECTION_TIMEOUT_MS}, PortKind};

pub struct TcpScanner {
    pub address: IpAddr,
    pub ports: PortKind,
    pub banner_grab: bool,
}

impl Scanner for TcpScanner {
    async fn scan(&self) -> Vec<super::ScanResult> {
        let (tx, rx) = mpsc::channel::<ScanResult>();

        let mut result = Vec::new();

        let ports_to_scan = match &self.ports {
            PortKind::List(ls) => ls.clone(),

            PortKind::Range(start, end) => (*start..=*end).collect()
        };

        for port in ports_to_scan {
            let tx = tx.clone();

            let addr = SocketAddr::new(self.address, port);

            tokio::spawn(async move {
                let connect_attempt = TcpStream::connect(addr);

                if let Ok(Ok(_stream)) = timeout(Duration::from_millis(CONNECTION_TIMEOUT_MS), connect_attempt).await {
                    tx.send(ScanResult::TcpOpen(port, None)).unwrap();
                };
            });
        }

        drop(tx);
        while let Ok(res) = rx.recv() {
            result.push(res);
        }
        result.sort_by_key(|res| {
            if let ScanResult::TcpOpen(port, _) = res {
                return *port;
            } else {
                return 0;
            }
        });

        result
    }

    fn get_target(&self) -> &IpAddr {
        &self.address
    }
}

impl TcpScanner {
    pub fn new(address: &String, ports: PortKind, banner_grab: bool) -> Result<Self, String> {
        let ip_address = match IpAddr::from_str(address) {
            Ok(ip) => ip,
            Err(_) => return Err(format!("Invalid Ip Address: {}", address))
        };

        Ok(
            TcpScanner {
            address: ip_address,
            ports,
            banner_grab
        }
    )
    }
}