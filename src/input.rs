use std::fs;

use clap::Parser;

use crate::{scanner::{ Scanner, TcpScanner}, PortKind};

#[derive(Parser)]
#[command(version, about, long_about=None)]
pub struct Args {
    /// List of target ip addresses, hostnames, or CIDRs separated by comma (,).
    #[arg(long, short, value_delimiter=',')]
    pub addresses: Vec<String>,

    /// List of ports to scan, separated by comma (,). Example: 80, 139, 443, 445
    #[arg(long, short, value_delimiter=',')]
    pub ports: Option<Vec<u16>>,
    
    /// Port range to scan. Example: 1-100
    #[arg(long, short, conflicts_with="ports", value_parser=range_parser)]
    pub range: Option<PortKind>,

    /// Perform banner grabbing
    #[arg(long, short)]
    pub banner: bool,
}



fn range_parser(input: &str) -> Result<PortKind, String> {
    let range = input
                        .split('-')
                        .map(str::parse)
                        .collect::<Result<Vec<u16>, std::num::ParseIntError>>();
    
    if range.is_err() {
        return Err(String::from("the range must be 'start-end'. Example: 1-100"));
    }

    match range.unwrap().as_slice() {
        [start, end] => Ok(PortKind::Range(*start, *end)),
        _ => Err(String::from("the range must be 'start-end'. Example: 1-100"))
    }
}



impl Args {
    pub fn to_scanners(self) -> Result<Vec<impl Scanner>, String> {
        if self.addresses.is_empty() {
            return Err("Error: Please provide a host target. Example: 10.6.2.211".to_string());
        }

        let ports;

        if self.ports.is_some() {
            ports = PortKind::List(self.ports.unwrap());
        } else if self.range.is_some() {
            ports = self.range.unwrap();
        } else {
            let file = match fs::read_to_string("default-ports.txt") {
                Ok(txt) => txt,
                Err(e) => return Err(e.to_string())
            };

            let port_list = match file.split(",")
                                .map(str::parse)
                                .collect::<Result<Vec<u16>, std::num::ParseIntError>>() {
                                    Ok(pts) => pts,
                                    Err(_) => return Err("Error: Failed parsing default ports".to_string())
                                };

            
            ports = PortKind::List(port_list);

        }

        let mut scanners = Vec::new();

        for address in self.addresses {
            let scn = TcpScanner::new(&address, ports.clone(), self.banner)?;

            scanners.push(scn);
        }

        Ok(scanners)
    }
}