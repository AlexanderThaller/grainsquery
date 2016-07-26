#![feature(custom_derive, plugin)]
#![plugin(serde_macros)]

extern crate serde;
extern crate serde_yaml;
extern crate glob;

use std::io::prelude::*;
use std::fs::File;
use std::io::Result;
use std::path::Path;
use std::collections::BTreeMap;
use std::vec::Vec;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use glob::glob;

#[derive(Debug, Serialize, Deserialize)]
struct Host {
    #[serde(default)]
    environment: String,
    id: String,
    ipv4: Vec<Ipv4Addr>,
    #[serde(default)]
    ipv6: Vec<Ipv6Addr>,
    kernelrelease: String,
    kernel: String,
    os_family: String,
    osrelease: String,
    os: String,
    #[serde(default)]
    realm: String,
    #[serde(default)]
    roles: Vec<String>,
    saltversion: String,
}

fn main() {
    let hosts: &mut BTreeMap<String, Host> = &mut BTreeMap::new();

    for entry in glob("./grains/*.yaml").expect("Failed to read glob pattern") {
        let host = match entry {
            Ok(path) => host_from_file(path.as_path()),
            Err(_) => BTreeMap::new(),
        };

        for (name, hostdata) in host {
            hosts.insert(name, hostdata);
        }
    }

    for (name, hostdata) in hosts {
        println!("{}: {:#?}", name, hostdata);
    }
}

fn file_to_string(filepath: &Path) -> Result<String> {
    let mut s = String::new();
    let mut f = try!(File::open(filepath));
    try!(f.read_to_string(&mut s));

    Ok(s)
}

fn host_from_file(filepath: &Path) -> BTreeMap<String, Host> {
    let data = file_to_string(filepath).unwrap();

    match serde_yaml::from_str(&data) {
        Ok(map) => map,
        Err(_) => BTreeMap::<String, Host>::new(),
    }
}
