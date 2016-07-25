#![feature(plugin)]
#![plugin(serde_macros)]
#![feature(custom_derive)]

extern crate serde;
extern crate serde_yaml;

use std::io::prelude::*;
use std::fs::File;
use std::io::Result;
use std::path::Path;
use std::collections::BTreeMap;

#[derive(Debug, Serialize, Deserialize)]
struct Host {
    id: String,
    realm: String,
    environment: String,
}

fn main() {
    let filepath = Path::new("aly3-dus.yaml");
    let data = file_to_string(filepath).unwrap();

    let deserialized_map: BTreeMap<String, Host> = serde_yaml::from_str(&data).unwrap();

    for (host, hostdata) in &deserialized_map {
        println!("{}: {:#?}", host, hostdata);
    }
}

fn file_to_string(filepath: &Path) -> Result<String> {
    let mut s = String::new();
    let mut f = try!(File::open(filepath));
    try!(f.read_to_string(&mut s));

    Ok(s)
}
