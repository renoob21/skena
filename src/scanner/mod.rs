use std::{net::IpAddr, sync::{mpsc, Arc}, vec};
pub use tcp_scanner::TcpScanner;

use crate::prober::ProbeRegistry;

mod tcp_scanner;

pub const CONNECTION_TIMEOUT_MS : u64 = 1000;

#[derive(Clone)]
pub enum PortKind {
    List(Vec<u16>),
    Range(u16, u16)
}

pub trait Scanner {
    async fn scan(&self) -> Vec<ScanResult>;

    fn get_target(&self) -> IpAddr;

    fn get_probers(&self) -> Arc<ProbeRegistry>;

    fn is_banner_grab(&self) -> bool;

    // fn get_ports(&self) -> Vec<u16>;
    
    async fn print_result(&self, results: Vec<ScanResult>) where Self: Sync {
        println!("Scan result for {}:", self.get_target());
        
        if self.is_banner_grab() {
            println!("{:10} {:15} {:100}", "port", "status", "banner");
            for res in results {
                match res {
                    ScanResult::TcpOpen(port, banner_opt) => {
                        let port = format!("{}\\tcp", port);
                        let mut status = "open";
                        let banner = match banner_opt {
                            Some(bn) => bn,
                            None => {
                                status = "open/filtered";
                                "-".to_string()
                            }
                        };

                        println!("{:10} {:15} {:100}", port, status, banner);

                    }
                    ScanResult::Closed => ()
                }

            }
        } else {
            println!("{:10} {:15}", "port", "status");

            for res in results {
                match res {
                    ScanResult::TcpOpen(port, _) => {
                        let port = format!("{}\\tcp", port);
                        let status = "open";
                        

                        println!("{:10} {:15}", port, status);

                    }
                    ScanResult::Closed => ()
                }

            }

        }
        
    }


    async fn probe(&self) -> Vec<ScanResult> {
        let scan_results = self.scan().await;
        let mut probe_results = Vec::new();
        let probe_registry = self.get_probers().clone();

        for res in scan_results {
            let port = match res {
                ScanResult::TcpOpen(prt,_ ) => prt,
                _ => continue
            };

            if let Some(prober_idxs) = probe_registry.port_map.get(&port).cloned() {
                let mut port_probing_result = Vec::new();
                let (tx, rx) = mpsc::channel::<ScanResult>();

                for idx in prober_idxs {
                    let inner_reg = Arc::clone(&probe_registry);
                    let target = self.get_target();
                    let tx = tx.clone();

                    tokio::spawn(async move {
                        let inner_reg = inner_reg;
                        let curr_prober = &inner_reg.owned_probes[idx];
                        let probe_res = curr_prober.probe(target, port).await;
                        
                        match probe_res {
                            ScanResult::TcpOpen(port, banner) => {
                                if let Some(bn) = banner {
                                    tx.send(ScanResult::TcpOpen(port, Some(bn))).unwrap();
                                }
                            }
                            ScanResult::Closed => (),
                        }
                    });
                }

                drop(tx);

                while let Ok(scan_res) = rx.recv() {
                    port_probing_result.push(scan_res);
                }

                if let Some(probed_res) = port_probing_result.pop() {
                    probe_results.push(probed_res);
                } else {
                    probe_results.push(res);
                }
            } else {
                probe_results.push(res);
            }
        }

        probe_results
    }

    async fn execute(&self) -> Vec<ScanResult> {
        if self.is_banner_grab() {
            self.probe().await
        } else {
            self.scan().await
        }
    }
}



#[derive(Debug)]
pub enum ScanResult {
    TcpOpen(u16, Option<String>),
    Closed,
}