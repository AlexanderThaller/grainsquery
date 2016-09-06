// MIT License
//
// Copyright (c) 2016 Alexander Thaller <alexander.thaller@trivago.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#![feature(custom_derive, plugin)]
#![plugin(serde_macros)]

extern crate serde;
extern crate serde_yaml;
extern crate serde_json;
extern crate glob;
extern crate env_logger;
extern crate regex;
extern crate loggerv;

#[macro_use]
extern crate log;

#[macro_use]
extern crate clap;

use clap::App;
use glob::glob;
use log::LogLevel;
use regex::Regex;
use std::collections::BTreeMap;
use std::env;
use std::fmt;
use std::fs::File;
use std::io::prelude::*;
use std::io::Result;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::path::Path;
use std::path::PathBuf;
use std::vec::Vec;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Cache {
    gitcommit: String,
    hosts: BTreeMap<String, Host>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
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

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} ({:?})", self.id, self.ipv4)
    }
}

impl Host {
    fn get_frontend_ip(&self) -> Option<Ipv4Addr> {
        for ip in self.ipv4.clone() {
            if is_frontend_ip(ip) {
                return Some(ip);
            }
        }

        None
    }
}

#[derive(Debug)]
struct Filter {
    environment: String,
    id_inverse: bool,
    id: String,
    os_family: String,
    productname: String,
    realm: String,
    roles: Vec<String>,
    saltversion: String,
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
            saltversion: String::new(),
            roles: Vec::new(),
        }
    }
}

#[derive(Debug)]
struct Warning {
    noenvironment: bool,
    norealm: bool,
    noroles: bool,
}

impl Warning {
    pub fn new() -> Warning {
        Warning {
            noenvironment: true,
            norealm: true,
            noroles: true,
        }
    }
}

fn main() {
    let yaml = load_yaml!("cli.yml");
    let app = App::from_yaml(yaml)
        .version(crate_version!())
        .get_matches();

    let matches = match app.subcommand.clone() {
        Some(subcommand) => subcommand.matches,
        None => app.clone(),
    };

    let loglevel: LogLevel = matches.value_of("loglevel")
        .unwrap_or("warn")
        .parse()
        .unwrap_or(LogLevel::Warn);

    loggerv::init_with_level(loglevel).unwrap();

    debug!("starting");
    debug!("matches: {:#?}", matches);

    let homepath = match env::home_dir() {
        Some(path) => path,
        None => PathBuf::from(""),
    };

    debug!("HomeDir: {}", homepath.display());

    let folderpath = match matches.value_of("folder") {
        Some(path) => PathBuf::from(path),
        None => homepath.join(".salt_grains"),
    };
    let folder = folderpath.as_path();
    debug!("folder: {:#?}", folder);

    let cachefilepath = match matches.value_of("cachefile") {
        Some(path) => PathBuf::from(path),
        None => homepath.join(".salt_grains_cache"),
    };
    let cachefile = cachefilepath.as_path();
    debug!("cachefile: {:#?}", cachefile);

    let usecache: bool = matches.value_of("cacheuse").unwrap_or("true").parse().unwrap_or(true);
    debug!("usecache: {}", usecache);

    let filter = Filter {
        environment: String::from(matches.value_of("environment").unwrap_or("")),
        id_inverse: matches.value_of("id_inverse").unwrap_or("false").parse().unwrap_or(false),
        id: String::from(matches.value_of("id").unwrap_or(".*")),
        os_family: String::from(matches.value_of("os_family").unwrap_or("")),
        productname: String::from(matches.value_of("productname").unwrap_or("")),
        realm: String::from(matches.value_of("realm").unwrap_or("")),
        roles: vec![String::from(matches.value_of("roles").unwrap_or(""))],
        saltversion: String::from(matches.value_of("saltversion").unwrap_or("")),
        ..Filter::new()
    };

    let warning = Warning {
        noenvironment: matches.value_of("noenvironment").unwrap_or("true").parse().unwrap_or(true),
        norealm: matches.value_of("norealm").unwrap_or("true").parse().unwrap_or(true),
        noroles: matches.value_of("noroles").unwrap_or("true").parse().unwrap_or(true),
        ..Warning::new()
    };

    debug!("filter: {:#?}", filter);
    debug!("warning: {:#?}", warning);

    let hosts = parse_hosts_or_use_cache(&folder, cachefile, usecache);

    // TODO: move this back into the filter_host function but avoid recompiling the regex for every
    // host (see example-avoid-compiling-the-same-regex-in-a-loop in the rust documentation about
    // the regex crate)
    let id_regex = Regex::new(filter.id.as_str()).unwrap();

    let hosts: BTreeMap<_, _> = hosts.iter()
        .filter(|&(_, host)| filter_host(host, &filter))
        .filter(|&(_, host)| id_regex.is_match(host.id.as_str()))
        .collect();

    match app.subcommand.clone() {
        Some(command) => {
            match command.name.as_str() {
                "list" => println!("{:#?}", hosts),
                "validate" => {
                    for (_, host) in &hosts {
                        warn_host(host, &warning)
                    }
                }
                "report" => render_report(&hosts, &filter),
                "ssh_hosts" => render_ssh_hosts(&hosts),
                _ => println!("{:#?}", hosts),
            }
        }
        None => println!("{:#?}", hosts),
    }
}

fn render_ssh_hosts(hosts: &BTreeMap<&String, &Host>) {
    for (id, host) in hosts {
        match host.get_frontend_ip() {
            Some(ip) => {
                println!("Host {}", id);
                println!("  Hostname: {}", ip);
                println!("");
            }
            None => warn!("Host {} has no frontend ip", id),
        }
    }
}

fn render_report(hosts: &BTreeMap<&String, &Host>, filter: &Filter) {
    let header = "
:toc: right
:toclevels: 3
:sectanchors:
:sectlink:
:icons: font
:linkattrs:
:numbered:
:idprefix:
:idseparator: -
:doctype: book
:source-highlighter: pygments
:listing-caption: Listing

= Report on Salt Minions";

    println!("{}", header);
    println!("== Filter\n{}", render_filter(filter));
}

fn render_filter(filter: &Filter) -> String {
    let environment = format!("Environment:: `{}`",
                              value_or_default(filter.environment.clone(), String::from("-")));
    let id_inverse = format!("ID Inverse:: `{}`", filter.id_inverse);
    let id = format!("ID:: `{}`",
                     value_or_default(filter.id.clone(), String::from("-")));
    let os_family = format!("OS Family:: `{}`",
                            value_or_default(filter.os_family.clone(), String::from("-")));
    let productname = format!("Product Name:: `{}`",
                              value_or_default(filter.productname.clone(), String::from("-")));
    let realm = format!("Realm:: `{}`",
                        value_or_default(filter.realm.clone(), String::from("-")));
    let roles = format!("Roles:: `{}`",
                        value_or_default_vec(filter.roles.clone(), String::from("-")));
    let saltversion = format!("Salt Version:: `{}`",
                              value_or_default(filter.saltversion.clone(), String::from("-")));

    format!("{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
            realm,
            environment,
            roles,
            id,
            id_inverse,
            os_family,
            productname)
}

fn value_or_default_vec(value: Vec<String>, fallback: String) -> String {
    if value.len() == 0 {
        fallback
    } else {
        value.join("* {}\n")
    }
}

fn value_or_default(value: String, fallback: String) -> String {
    if value == "" {
        fallback
    } else {
        value
    }
}

fn parse_hosts_or_use_cache(folder: &Path,
                            cachefile: &Path,
                            usecache: bool)
                            -> BTreeMap<String, Host> {
    if usecache {
        if cachefile.exists() {
            match read_cache_check_refresh(folder, cachefile) {
                Some(cache) => cache.hosts,
                None => parse_hosts_from_folder(folder),
            }
        } else {
            let hosts = parse_hosts_from_folder(folder);
            let cache = Cache {
                gitcommit: get_current_commit_for_grains(folder),
                hosts: hosts.clone(),
            };

            write_cache(cachefile, &cache);
            hosts
        }
    } else {
        parse_hosts_from_folder(folder)
    }
}

fn get_current_commit_for_grains(folder: &Path) -> String {
    let path = folder.join(".git").join("FETCH_HEAD");
    let data = file_to_string(&path).unwrap();

    debug!("git fetch_head: {:#?}", data);

    let commit = data.split_whitespace().next().unwrap();

    debug!("git commit: {:#?}", commit);

    String::from(commit)
}

fn read_cache_check_refresh(folder: &Path, cachefile: &Path) -> Option<Cache> {
    let commit = get_current_commit_for_grains(folder);

    match read_cache(cachefile) {
        None => None,
        Some(cache) => {
            if cache.gitcommit != commit {
                let hosts = parse_hosts_from_folder(folder);
                let newcache = Cache {
                    gitcommit: commit,
                    hosts: hosts.clone(),
                };

                write_cache(cachefile, &newcache);
                Some(newcache)

            } else {
                Some(cache)
            }
        }
    }
}

fn read_cache(cachefile: &Path) -> Option<Cache> {
    let data = file_to_string(cachefile).unwrap();

    match serde_yaml::from_str(&data) {
        Ok(cache) => Some(cache),
        Err(_) => None,
    }
}

fn write_cache(cachefile: &Path, cache: &Cache) {
    let data = serde_json::to_string(&cache).unwrap();

    debug!("data: {:#?}", data);

    let mut file = File::create(cachefile).unwrap();
    file.write_all(data.as_bytes()).unwrap();
}

fn warn_host(host: &Host, warning: &Warning) {
    if warning.noenvironment && host.environment.is_empty() {
        warn!("host {} has no environment", host)
    }

    if warning.norealm && host.realm.is_empty() {
        warn!("host {} has no realm", host)
    }

    if warning.noroles && host.roles.is_empty() {
        warn!("host {} has no roles", host)
    }
}

fn filter_host(host: &Host, filter: &Filter) -> bool {
    let filters: Vec<bool> = vec!(
        empty_or_matching(&host.environment, &filter.environment),
        empty_or_matching(&host.os_family, &filter.os_family),
        empty_or_matching(&host.productname, &filter.productname),
        empty_or_matching(&host.realm, &filter.realm),
        empty_or_matching(&host.saltversion, &filter.saltversion),
        );

    filters.iter()
        .fold(true, |acc, &x| acc && x)
}

fn empty_or_matching(value: &String, filter: &String) -> bool {
    if filter == "" {
        return true;
    }

    return value == filter;
}

fn parse_hosts_from_folder(folder: &Path) -> BTreeMap<String, Host> {
    let mut hosts: BTreeMap<String, Host> = BTreeMap::new();

    let files = format!("{}/*.yaml", folder.display());
    for entry in glob(files.as_str()).expect("Failed to read glob pattern") {
        let host = match entry {
            Ok(path) => host_from_file(path.as_path()),
            Err(_) => BTreeMap::new(),
        };

        for (name, hostdata) in host {
            hosts.insert(name, hostdata);
        }
    }

    return hosts;
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

fn is_frontend_ip(ip: Ipv4Addr) -> bool {
    match (ip.octets()[0], ip.octets()[1]) {
        (10, 1) => true,
        (10, 11) => true,
        (10, 21) => true,
        (10, 31) => true,
        (192, 168) => true,
        _ => false,
    }
}
