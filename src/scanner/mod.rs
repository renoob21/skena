use std::{ io::{ BufReader, Read}, net::{IpAddr, TcpStream}, sync::mpsc, thread, time::Duration};
pub use tcp_scanner::TcpScanner;

mod tcp_scanner;

const CONNECTION_TIMEOUT_MS : u64 = 1000;

#[derive(Clone)]
pub enum PortKind {
    List(Vec<u16>),
    Range(u16, u16)
}

pub trait Scanner {
    async fn scan(&self) -> Vec<ScanResult>;

    fn get_target(&self) -> &IpAddr;
    
    async fn print_result(&self, results: Vec<ScanResult>) {
        println!("Scan result for {}:", self.get_target());
        for res in results {
            println!("{:?}", res);
        }
    }
}



#[derive(Debug)]
pub enum ScanResult {
    TcpOpen(u16, Option<String>),
    Closed,
}