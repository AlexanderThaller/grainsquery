#![feature(custom_derive, plugin)]
#![plugin(serde_macros)]

extern crate serde;
extern crate serde_yaml;
extern crate glob;
extern crate env_logger;

#[macro_use]
extern crate log;

#[macro_use]
extern crate clap;

use std::io::prelude::*;
use std::fs::File;
use std::io::Result;
use std::path::Path;
use std::collections::BTreeMap;
use std::vec::Vec;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use glob::glob;
use clap::App;

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
    productname: String,
}

#[derive(Debug)]
struct Filter {
    environment: String,
    id: String,
    id_inverse: bool,
    os_family: String,
    productname: String,
    realm: String,
}

impl Filter {
    pub fn new() -> Filter {
        Filter {
            environment: String::new(),
            id: String::new(),
            id_inverse: false,
            os_family: String::new(),
            productname: String::new(),
            realm: String::new(),
        }
    }
}

fn main() {
    env_logger::init().unwrap();

    let yaml = load_yaml!("cli.yml");
    let matches = App::from_yaml(yaml).get_matches();
    debug!("matches: {:#?}", matches);

    let folder = matches.value_of("folder").unwrap_or("grains");

    let filter = Filter {
        environment: String::from(matches.value_of("environment").unwrap_or("")),
        ..Filter::new()
    };

    debug!("folder: {:#?}", folder);
    debug!("filter: {:#?}", filter);

    let hosts: BTreeMap<_, _> = parse_hosts_from_folder(folder).into_iter()
        .filter(|&(_, host)| host.environment != filter.environment)
        .collect();

    println!("{:#?}", hosts)
}

fn parse_hosts_from_folder(folder: &str) -> BTreeMap<String, Host> {
    let mut hosts: BTreeMap<String, Host> = BTreeMap::new();

    let files = format!("./{}/*.yaml", folder);
    for entry in glob(files.as_str()).expect("Failed to read glob pattern") {
        let host = match entry {
            Ok(path) => host_from_file(path.as_path()),
            Err(_) => BTreeMap::new(),
        };

        for (name, hostdata) in host {
            hosts.insert(name, hostdata);
        }
    }

    return hosts
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
