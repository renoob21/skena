# skena

Simple port scanner written in rust

I only made this project for fun and using it to learn basic about port scanning and how to handle connection in rust. Currently it only supports TCP Scanning. However, I am planning to add some functionalities such as UDP scanning and SYN scanning.

## Installation

First, you need to get rustup toolchain. You can get it [here](https://www.rust-lang.org/tools/install).

Then you can clone this github repository to your local files

```
git clone https://github.com/renoob21/skena.git
```

Compile the file using cargo:

```
cd skena
cargo build --release
```

## Usage

There are several options that can be used within the application. To show the help, use:

```
~$ ./target/release/skena.exe -h
Usage: skena.exe [OPTIONS]

Options:
  -a, --addresses <ADDRESSES>  List of target ip addresses, hostnames, or CIDRs separated by comma (,)
  -p, --ports <PORTS>          List of ports to scan, separated by comma (,). Example: 80, 139, 443, 445
  -r, --range <RANGE>          Port range to scan. Example: 1-100
  -b, --banner                 Perform banner grabbing
  -h, --help                   Print help
  -V, --version                Print version
```

### Example

Use skena to scan google.com:

```
~$ ./target/release/skena.exe -a 216.239.38.120
Scan result for 216.239.38.120:
port       status
80\tcp     open
443\tcp    open
```