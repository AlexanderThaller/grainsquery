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
extern crate time;

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
    #[serde(default)]
    ipv4: Vec<Ipv4Addr>,
    #[serde(default)]
    ipv6: Vec<Ipv6Addr>,
    #[serde(default)]
    kernelrelease: String,
    #[serde(default)]
    kernel: String,
    #[serde(default)]
    os_family: String,
    #[serde(default)]
    osrelease: String,
    #[serde(default)]
    os: String,
    #[serde(default)]
    realm: String,
    #[serde(default)]
    roles: Vec<String>,
    #[serde(default)]
    saltversion: String,
    #[serde(default)]
    productname: String,
    #[serde(default)]
    saltmaster: String,
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} ({:?})", self.id, self.ipv4)
    }
}

impl Host {
    fn get_full_os(&self) -> String {
        format!("{} {}", self.os, self.osrelease)
    }

    fn get_full_kernel(&self) -> String {
        format!("{} {}", self.kernel, self.kernelrelease)
    }

    fn get_ip(&self, lookup: &str) -> Option<Ipv4Addr> {
        for ip in self.ipv4.clone() {
            let split: Vec<_> = lookup.split(':').collect();
            let base = match split.get(0) {
                Some(d) => d,
                None => "firewall",
            };

            let detail = match split.get(1) {
                Some(d) => d,
                None => "base_pattern",
            };

            let matcher = match base {
                "firewall" => {
                    match detail {
                        "frontend" => {
                            match (ip.octets()[0], ip.octets()[1], ip.octets()[2]) {
                                (10, 1, 5) => Some(ip),
                                (10, 1, 2) => Some(ip),
                                (10, 11, 2) => Some(ip),
                                (10, 11, 12) => Some(ip),
                                (10, 21, 2) => Some(ip),
                                (10, 31, 2) => Some(ip),
                                (192, 168, _) => Some(ip),
                                (10, 1, 13) => Some(ip),
                                (10, 1, 12) => Some(ip),
                                (10, 1, 11) => Some(ip),
                                (10, 1, 10) => Some(ip),
                                (10, 1, 9) => Some(ip),
                                (10, 1, 8) => Some(ip),
                                _ => None,
                            }
                        }
                        "backend" => {
                            match (ip.octets()[0], ip.octets()[1], ip.octets()[2]) {
                                (10, 1, 3) => Some(ip),
                                (10, 11, 3) => Some(ip),
                                (10, 21, 3) => Some(ip),
                                (10, 31, 3) => Some(ip),
                                (192, 168, _) => Some(ip),
                                (172, _, _) => Some(ip),
                                _ => None,
                            }
                        }
                        "admin" => {
                            match (ip.octets()[0], ip.octets()[1], ip.octets()[2]) {
                                (10, 1, 6) => Some(ip),
                                (10, 11, 6) => Some(ip),
                                (10, 21, 6) => Some(ip),
                                (10, 31, 6) => Some(ip),
                                (192, 168, _) => Some(ip),
                                (172, _, _) => Some(ip),
                                _ => None,
                            }
                        }
                        _ => {
                            match (ip.octets()[0], ip.octets()[1]) {
                                (10, 1) => Some(ip),
                                (10, 11) => Some(ip),
                                (10, 21) => Some(ip),
                                (10, 31) => Some(ip),
                                (192, 168) => Some(ip),
                                (172, _) => Some(ip),
                                _ => None,
                            }
                        }
                    }
                }
                "backbone" => {
                    match detail {
                        "admin" => {
                            match (ip.octets()[0], ip.octets()[1], ip.octets()[2]) {
                                (10, 2, 6) => Some(ip),
                                (10, 12, 6) => Some(ip),
                                (10, 22, 6) => Some(ip),
                                (10, 32, 6) => Some(ip),
                                (192, 168, _) => Some(ip),
                                (172, _, _) => Some(ip),
                                _ => None,
                            }
                        }
                        "frontend" => {
                            match (ip.octets()[0], ip.octets()[1], ip.octets()[2]) {
                                (10, 2, 5) => Some(ip),
                                (10, 2, 2) => Some(ip),
                                (10, 12, 2) => Some(ip),
                                (10, 22, 2) => Some(ip),
                                (10, 32, 2) => Some(ip),
                                (192, 168, _) => Some(ip),
                                (172, _, _) => Some(ip),
                                _ => None,
                            }
                        }
                        "backend" => {
                            match (ip.octets()[0], ip.octets()[1], ip.octets()[2]) {
                                (10, 2, 3) => Some(ip),
                                (10, 12, 3) => Some(ip),
                                (10, 22, 3) => Some(ip),
                                (10, 32, 3) => Some(ip),
                                (192, 168, _) => Some(ip),
                                (172, _, _) => Some(ip),
                                _ => None,
                            }
                        }
                        _ => {
                            match (ip.octets()[0], ip.octets()[1]) {
                                (10, 2) => Some(ip),
                                (10, 12) => Some(ip),
                                (10, 22) => Some(ip),
                                (10, 32) => Some(ip),
                                (192, 168) => Some(ip),
                                (172, _) => Some(ip),
                                _ => None,
                            }
                        }
                    }
                }
                _ => None,
            };

            if matcher.is_some() {
                return matcher;
            };
        }

        None
    }

    fn get_reachable_ip(&self) -> Option<Ipv4Addr> {
        let lookups = vec![
            "firewall:frontend",
            "firewall:admin",
            "firewall:backend",
            "firewall",
        ];

        for lookup in lookups {
            let ip = self.get_ip(lookup);

            if ip.is_some() {
                debug!("lookup: {}, ip: {}", lookup, ip.unwrap());
                return ip;
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
    roles_mode: String,
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
            roles_mode: String::new(),
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

    let loglevel: LogLevel = matches.value_of("log_level")
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

    let folderpath = match matches.value_of("folder_grains") {
        Some(path) => PathBuf::from(path),
        None => homepath.join(".salt_grains"),
    };
    let folder = folderpath.as_path();
    debug!("folder: {:#?}", folder);

    let cachefilepath = match matches.value_of("cache_file") {
        Some(path) => PathBuf::from(path),
        None => homepath.join(".salt_grains_cache"),
    };
    let cachefile = cachefilepath.as_path();
    debug!("cachefile: {:#?}", cachefile);

    let usecache: bool = matches.value_of("cache_use").unwrap_or("true").parse().unwrap_or(true);
    debug!("usecache: {}", usecache);

    let cache_force_refresh: bool =
        matches.value_of("cache_force_refresh").unwrap_or("false").parse().unwrap_or(false);
    debug!("cache_force_refresh:: {}", cache_force_refresh);

    let generate_hosts: bool =
        matches.value_of("generate_hosts").unwrap_or("true").parse().unwrap_or(true);
    debug!("generate_hosts: {}", generate_hosts);

    let filter = Filter {
        environment: String::from(matches.value_of("filter_environment").unwrap_or("")),
        id_inverse: matches.value_of("filter_id_inverse")
            .unwrap_or("false")
            .parse()
            .unwrap_or(false),
        id: String::from(matches.value_of("filter_id").unwrap_or(".*")),
        os_family: String::from(matches.value_of("filter_os_family").unwrap_or("")),
        productname: String::from(matches.value_of("filter_productname").unwrap_or("")),
        realm: String::from(matches.value_of("filter_realm").unwrap_or("")),
        roles: values_t!(matches.values_of("filter_roles"), String).unwrap_or(Vec::new()),
        roles_mode: String::from(matches.value_of("filter_roles_mode").unwrap_or("one")),
        saltversion: String::from(matches.value_of("filter_saltversion").unwrap_or("")),
        ..Filter::new()
    };

    let warning = Warning {
        noenvironment: matches.value_of("warn_noenvironment")
            .unwrap_or("true")
            .parse()
            .unwrap_or(true),
        norealm: matches.value_of("warn_norealm").unwrap_or("true").parse().unwrap_or(true),
        noroles: matches.value_of("warn_noroles").unwrap_or("true").parse().unwrap_or(true),
        ..Warning::new()
    };

    debug!("filter: {:#?}", filter);
    debug!("warning: {:#?}", warning);

    let hosts = parse_hosts_or_use_cache(&folder, cachefile, usecache, cache_force_refresh);

    debug!("Hosts Length: {}", hosts.len());

    // TODO: move this back into the filter_host function but avoid recompiling the regex for every
    // host (see example-avoid-compiling-the-same-regex-in-a-loop in the rust documentation about
    // the regex crate)
    let id_regex = Regex::new(filter.id.as_str()).unwrap();

    let hosts: BTreeMap<_, _> = hosts.iter()
        .filter(|&(_, host)| filter_host(host, &filter))
        .filter(|&(_, host)| id_regex.is_match(host.id.as_str()))
        .collect();

    debug!("Filtered Hosts Length: {}", hosts.len());

    match app.subcommand.clone() {
        Some(command) => {
            match command.name.as_str() {
                "list" => println!("{:#?}", hosts),
                "validate" => {
                    for (_, host) in hosts {
                        warn_host(host, &warning)
                    }
                }
                "report" => render_report(hosts, filter, folder, generate_hosts),
                "ssh_hosts" => {
                    let prefix = matches.value_of("hosts_prefix").unwrap_or("");
                    render_ssh_hosts(hosts, prefix);
                }
                _ => println!("{:#?}", hosts),
            }
        }
        None => println!("{:#?}", hosts),
    }
}

fn render_ssh_hosts(hosts: BTreeMap<&String, &Host>, prefix: &str) {
    let host_prefix = match prefix {
        "" => String::from(""),
        _ => String::from(prefix) + ".",
    };

    for (id, host) in hosts {
        match host.get_reachable_ip() {
            Some(ip) => {
                println!("Host {}{}", host_prefix, id);
                println!("  Hostname {}", ip);
                println!("");
            }
            None => warn!("Host {} has no frontend ip", id),
        }
    }
}

fn render_report(hosts: BTreeMap<&String, &Host>,
                 filter: Filter,
                 folder: &Path,
                 generate_hosts: bool) {
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

= Report on Salt Minions\n";

    println!("{}", header);
    println!("== Filter\n{}", render_filter(&filter));
    println!("");

    println!("== Overview");
    println!("Total Host Count:: {}", hosts.len());
    println!("Generated:: {}", time::now().rfc3339());
    println!("Git Commit:: `{}`", get_current_commit_for_grains(folder));
    println!("Grainsquery Version:: `{}`", crate_version!());
    println!("");

    println!("== Realms");
    let mut realms: BTreeMap<String, u32> = BTreeMap::default();
    for (_, host) in hosts.iter() {
        *realms.entry(host.realm.clone()).or_insert(0) += 1;
    }
    println!("Total:: {}", realms.len());
    println!("\n{}",
             render_key_value_list(&realms, "Realm".into(), "Count".into()));
    println!("");

    println!("== Environments");
    let mut environments: BTreeMap<String, u32> = BTreeMap::default();
    for (_, host) in hosts.iter() {
        *environments.entry(host.environment.clone()).or_insert(0) += 1;
    }
    println!("Total:: {}", environments.len());
    println!("\n{}",
             render_key_value_list(&environments, "Environment".into(), "Count".into()));
    println!("");

    println!("== Salt Versions");
    let mut salts: BTreeMap<String, u32> = BTreeMap::default();
    for (_, host) in hosts.iter() {
        *salts.entry(host.saltversion.clone()).or_insert(0) += 1;
    }
    println!("Total:: {}", salts.len());
    println!("\n{}",
             render_key_value_list(&salts, "Salt Version".into(), "Count".into()));
    println!("");

    println!("== Saltmaster");
    let mut saltmaster: BTreeMap<String, u32> = BTreeMap::default();
    for (_, host) in hosts.iter() {
        *saltmaster.entry(host.saltmaster.clone()).or_insert(0) += 1;
    }
    println!("Total:: {}", saltmaster.len());
    println!("\n{}",
             render_key_value_list(&saltmaster, "Master".into(), "Count".into()));
    println!("");

    println!("== Products");
    let mut products: BTreeMap<String, u32> = BTreeMap::default();
    for (_, host) in hosts.iter() {
        let filtered = filter_lines_beginning_with(&host.productname, "#");
        *products.entry(filtered).or_insert(0) += 1;
    }
    println!("Total:: {}", products.len());
    println!("\n{}",
             render_key_value_list(&products, "Product".into(), "Count".into()));
    println!("");

    println!("== Roles");
    let mut roles: BTreeMap<String, u32> = BTreeMap::default();
    for (_, host) in hosts.iter() {
        for role in host.roles.iter() {
            *roles.entry(role.clone()).or_insert(0) += 1;
        }
    }
    println!("Total:: {}", roles.len());
    println!("\n{}",
             render_key_value_list(&roles, "Salt Version".into(), "Count".into()));
    println!("");

    println!("== OS");
    println!("=== OS Family");
    let mut os_families: BTreeMap<String, u32> = BTreeMap::default();
    for (_, host) in hosts.iter() {
        *os_families.entry(host.os_family.clone()).or_insert(0) += 1;
    }
    println!("Total:: {}", os_families.len());
    println!("\n{}",
             render_key_value_list(&os_families, "OS Family".into(), "Count".into()));
    println!("");

    println!("=== OS");
    let mut os: BTreeMap<String, u32> = BTreeMap::default();
    for (_, host) in hosts.iter() {
        *os.entry(host.get_full_os()).or_insert(0) += 1;
    }
    println!("Total:: {}", os.len());
    println!("\n{}",
             render_key_value_list(&os, "OS".into(), "Count".into()));
    println!("");

    println!("=== Kernel Family");
    let mut kernel_families: BTreeMap<String, u32> = BTreeMap::default();
    for (_, host) in hosts.iter() {
        *kernel_families.entry(host.kernel.clone()).or_insert(0) += 1;
    }
    println!("Total:: {}", kernel_families.len());
    println!("\n{}",
             render_key_value_list(&kernel_families, "Kernel Family".into(), "Count".into()));
    println!("");

    println!("=== Kernel");
    let mut kernels: BTreeMap<String, u32> = BTreeMap::default();
    for (_, host) in hosts.iter() {
        *kernels.entry(host.get_full_kernel()).or_insert(0) += 1;
    }
    println!("Total:: {}", kernels.len());
    println!("\n{}",
             render_key_value_list(&kernels, "Kernel".into(), "Count".into()));
    println!("");

    println!("=== IPs");
    let mut ips: BTreeMap<String, u32> = BTreeMap::default();
    for (_, host) in hosts.iter() {
        if host.ipv4.len() != 0 {
            *ips.entry("IPv4".into()).or_insert(0) += 1;
        }

        if host.ipv6.len() != 0 {
            *ips.entry("IPv6".into()).or_insert(0) += 1;
        }
    }
    println!("\n{}",
             render_key_value_list(&ips, "Version".into(), "Count".into()));
    println!("");

    if !generate_hosts {
        return;
    }

    println!("== Hosts");
    for (id, host) in hosts {
        println!("=== {}", id);
        println!("Realm:: {}", host.realm);
        println!("Environment:: {}", host.environment);
        println!("Salt Version:: {}", host.saltversion);
        println!("Saltmaster:: {}", host.saltmaster);
        println!("Operating System:: {}", host.get_full_os());
        println!("Kernel:: {}", host.get_full_kernel());
        println!("Product Name:: {}", host.productname);
        if host.roles.len() != 0 {
            println!("\n==== Roles\n{}", render_list(&host.roles));
        }

        println!("==== IPs");
        match host.get_reachable_ip() {
            Some(ip) => println!("Reachable:: `{}`", ip),
            None => {}
        }
        println!("");

        let lookups = vec![
            "firewall",
            "firewall:admin",
            "firewall:backend",
            "firewall:frontend",
        ];

        println!("===== Lookup");
        for lookup in lookups {
            match host.get_ip(lookup) {
                Some(ip) => println!("{}:: `{}`", lookup, ip),
                None => {}
            }
        }

        println!("");

        if host.ipv4.len() != 0 {
            println!("===== IPv4\n{}", render_list(&host.ipv4));
        }

        if host.ipv6.len() != 0 {
            println!("===== IPv6\n{}", render_list(&host.ipv6));
        }

    }
}

fn render_list<A: std::fmt::Display>(list: &Vec<A>) -> String {
    let mut out = String::new();

    for line in list {
        out.push_str(format!("* `{}`\n", line).as_str());
    }

    out
}

fn filter_lines_beginning_with(lines: &String, beginning: &str) -> String {
    let mut out = String::new();

    for line in lines.split("\n") {
        if !line.starts_with(beginning) {
            out.push_str(line);
        }
    }

    out
}

fn render_key_value_list(list: &BTreeMap<String, u32>,
                         header_key: String,
                         header_value: String)
                         -> String {
    let mut table = String::new();

    for (key, value) in list {
        table.push_str(format!("|{}|{}\n", key, value).as_str());
    }

    format!("[cols=\"2*\", options=\"header\"]\n|===\n|{}|{}\n{}|===",
            header_key,
            header_value,
            table)
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

    format!("{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
            realm,
            environment,
            roles,
            id,
            id_inverse,
            os_family,
            productname,
            saltversion)
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
                            usecache: bool,
                            cache_force_refresh: bool)
                            -> BTreeMap<String, Host> {
    if usecache {
        debug!("use cache");
        if !cache_force_refresh && cachefile.exists() {
            debug!("Read cache");
            match read_cache_check_refresh(folder, cachefile) {
                Some(cache) => cache.hosts,
                None => parse_hosts_from_folder(folder),
            }
        } else {
            debug!("Read hosts");
            let hosts = parse_hosts_from_folder(folder);
            let cache = Cache {
                gitcommit: get_current_commit_for_grains(folder),
                hosts: hosts.clone(),
            };

            write_cache(cachefile, &cache);
            hosts
        }
    } else {
        debug!("don't use cache");
        parse_hosts_from_folder(folder)
    }
}

fn get_current_commit_for_grains(folder: &Path) -> String {
    let path = folder.join(".git").join("ORIG_HEAD");
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
        contains_one(&host.roles, &filter.roles),
        );

    filters.iter()
        .fold(true, |acc, &x| acc && x)
}

fn contains_one<T: std::cmp::PartialEq>(source: &Vec<T>, search: &Vec<T>) -> bool {
    if search.len() == 0 {
        return true;
    }

    for entry in search {
        if source.contains(&entry) {
            return true;
        }
    }

    return false;
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
        Err(err) => {
            error!("can not parse grains for file {}: {}",
                   filepath.file_name().unwrap().to_str().unwrap(),
                   err);
            BTreeMap::<String, Host>::new()
        }
    }
}
