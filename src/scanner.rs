use std::{ net::TcpStream, sync::mpsc, thread, time::Duration};

#[derive(Clone)]
pub enum PortKind {
    List(Vec<u16>),
    Range(u16, u16)
}

pub struct ScanConfig {
    pub addresses: Vec<String>,
    pub ports: PortKind,
}

impl ScanConfig {
    pub fn scan(&self) {
        for add in self.addresses.clone() {
            tcp_scan(add, self.ports.clone());
        }
    }
}

fn tcp_scan(address: String, ports: PortKind) {
    let (tx, rx) = mpsc::channel::<u16>();

    println!("Start scanning for host: {}", address);

    match ports {
        PortKind::List(port_list) => {
            for port in port_list {
                let tx = tx.clone();
                let address = address.clone();
                thread::spawn(move || {
                    tcp_port_scan(tx, address, port);
                });
            }
        }
        PortKind::Range(start, end) => {
            for port in start..(end+1) {
                let tx = tx.clone();
                let address = address.clone();
                thread::spawn(move || {
                    tcp_port_scan(tx, address, port);
                });
            }
        }
    }

    let mut open_ports = Vec::new();
    drop(tx);
    for p in rx {
        open_ports.push(p);
    }

    println!("Open ports: {:?}", open_ports);

    

}

fn tcp_port_scan(tx: mpsc::Sender<u16>, address: String, port: u16) {
    let socket = format!("{}:{}", address, port);

    match TcpStream::connect_timeout(&socket.parse().unwrap(), Duration::from_secs(1)) {
        Ok(_) => {
            tx.send(port).unwrap();
        }
        Err(_) => ()
    }
}