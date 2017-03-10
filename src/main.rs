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

extern crate serde;
extern crate serde_json;
extern crate glob;
extern crate env_logger;
extern crate regex;
extern crate loggerv;
extern crate time;
extern crate host;

#[macro_use]
extern crate log;

#[macro_use]
extern crate clap;

#[macro_use]
extern crate serde_derive;

use clap::App;
use glob::glob;
use log::LogLevel;
use regex::Regex;
use std::collections::BTreeMap as Map;
use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::io::Result;
use std::net::Ipv4Addr;
use std::path::Path;
use std::path::PathBuf;
use std::vec::Vec;
use std::str::FromStr;
use host::Host;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Cache {
    gitcommit: String,
    hosts: Map<String, Host>,
}

#[derive(Default, Debug, Serialize, Deserialize, Clone)]
struct Count {
    count: u32,
    name: String,
}

#[derive(Debug)]
struct Filter {
    applications_mode: String,
    applications: Vec<String>,
    environment: String,
    id_inverse: bool,
    id: String,
    ipv4: Ipv4Addr,
    os_family: String,
    productname: String,
    realm: String,
    roles_mode: String,
    roles: Vec<String>,
    saltmaster: String,
    saltversion: String,
    serialnumber: String,
    isvirtual: String,
}

impl Default for Filter {
    fn default() -> Filter {
        Filter {
            applications: Vec::new(),
            applications_mode: String::new(),
            environment: String::new(),
            id: String::new(),
            id_inverse: false,
            os_family: String::new(),
            productname: String::new(),
            realm: String::new(),
            saltversion: String::new(),
            roles: Vec::new(),
            roles_mode: String::new(),
            saltmaster: String::new(),
            ipv4: Ipv4Addr::new(0, 0, 0, 0),
            serialnumber: String::new(),
            isvirtual: String::new(),
        }
    }
}

#[derive(Debug, Default)]
struct Warning {
    noenvironment: bool,
    norealm: bool,
    noroles: bool,
    nosaltmaster: bool,
    noipv6: bool,
    different_master: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct Ret {
    jid: String,
    retcode: usize,
    ret: Host,
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

    let report_hosts: bool =
        matches.value_of("report_hosts").unwrap_or("true").parse().unwrap_or(true);
    debug!("report_hosts: {}", report_hosts);

    let filter = Filter {
        applications: values_t!(matches.values_of("filter_applications"), String)
            .unwrap_or(Vec::new()),
        applications_mode: String::from(matches.value_of("filter_applications_mode")
            .unwrap_or("one")),
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
        saltmaster: String::from(matches.value_of("filter_saltmaster").unwrap_or("")),
        serialnumber: String::from(matches.value_of("filter_serialnumber").unwrap_or("")),
        ipv4: Ipv4Addr::from_str(matches.value_of("filter_ip").unwrap_or(""))
            .unwrap_or_else(|_| Ipv4Addr::new(0, 0, 0, 0)),
        isvirtual: String::from(matches.value_of("filter_isvirtual").unwrap_or("")),
    };

    let warning = Warning {
        noenvironment: matches.value_of("warn_noenvironment")
            .unwrap_or("true")
            .parse()
            .unwrap_or(true),
        norealm: matches.value_of("warn_norealm").unwrap_or("true").parse().unwrap_or(true),
        noroles: matches.value_of("warn_noroles").unwrap_or("true").parse().unwrap_or(true),
        nosaltmaster: matches.value_of("warn_nosaltmaster")
            .unwrap_or("true")
            .parse()
            .unwrap_or(true),
        noipv6: matches.value_of("warn_noipv6")
            .unwrap_or("true")
            .parse()
            .unwrap_or(true),
        different_master: matches.value_of("warn_different_master")
            .unwrap_or("true")
            .parse()
            .unwrap_or(true),
    };

    debug!("filter: {:#?}", filter);
    debug!("warning: {:#?}", warning);

    let hosts = parse_hosts_or_use_cache(folder, cachefile, usecache, cache_force_refresh);

    debug!("Hosts Length: {}", hosts.len());

    // TODO: move this back into the filter_host function but avoid recompiling the regex for every
    // host (see example-avoid-compiling-the-same-regex-in-a-loop in the rust documentation about
    // the regex crate)
    let id_regex = Regex::new(filter.id.as_str()).unwrap();
    let saltversion_regex = Regex::new(filter.saltversion.as_str()).unwrap();

    let hosts: Map<_, _> = hosts.iter()
        .filter(|&(_, host)| filter_host(host, &filter))
        .filter(|&(_, host)| id_regex.is_match(host.id.as_str()))
        .filter(|&(_, host)| saltversion_regex.is_match(host.saltversion.as_str()))
        .collect();

    debug!("Filtered Hosts Length: {}", hosts.len());

    match app.subcommand.clone() {
        Some(command) => {
            match command.name.as_str() {
                "list" => {
                    let format = matches.value_of("output_format").unwrap_or("default");
                    match format {
                        "json" => {
                            println!("{}",
                                     serde_json::to_string(&hosts)
                                         .expect("can not convert hosts to json for listing the \
                                                  hosts"))
                        }
                        _ => println!("{:#?}", hosts),
                    }
                }
                "validate" => {
                    for host in hosts.values() {
                        warn_host(host, &warning)
                    }
                }
                "aggregate" => {
                    match command.matches.subcommand {
                        Some(command) => {
                            match command.name.as_str() {
                                "roles" => aggregate_roles(hosts),
                                "realm" => aggregate_realm(hosts),
                                "environment" => aggregate_environment(hosts),
                                _ => unreachable!(),
                            }
                        }
                        None => aggregate(hosts),
                    }
                }
                "report" => render_report(hosts, filter, folder, report_hosts),
                "ssh_hosts" => {
                    let prefix = matches.value_of("hosts_prefix").unwrap_or("");
                    render_ssh_hosts(hosts, prefix, folder);
                }
                _ => unreachable!(),
            }
        }
        None => println!("{:#?}", hosts),
    }
}

fn render_ssh_hosts(hosts: Map<&String, &Host>, prefix: &str, folder: &Path) {
    let host_prefix = match prefix {
        "" => String::from(""),
        _ => String::from(prefix) + ".",
    };

    println!("# generated: {}", time::now().rfc3339());
    println!("# git commit: {}", get_current_commit_for_grains(folder));
    println!("# grainsquery version: {}", crate_version!());
    println!("");

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

fn render_report(hosts: Map<&String, &Host>, filter: Filter, folder: &Path, report_hosts: bool) {
    let mut realms: Map<String, u32> = Map::default();
    let mut environments: Map<String, u32> = Map::default();
    let mut salts: Map<String, u32> = Map::default();
    let mut saltmaster: Map<String, u32> = Map::default();
    let mut products: Map<String, u32> = Map::default();
    let mut roles: Map<String, u32> = Map::default();
    let mut role_combinations: Map<String, u32> = Map::default();
    let mut applications: Map<String, u32> = Map::default();
    let mut os_families: Map<String, u32> = Map::default();
    let mut os: Map<String, u32> = Map::default();
    let mut kernel_families: Map<String, u32> = Map::default();
    let mut kernels: Map<String, u32> = Map::default();
    let mut ips: Map<String, u32> = Map::default();
    let mut isvirtual: Map<String, u32> = Map::default();

    for host in hosts.values() {
        *realms.entry(host.realm.clone()).or_insert(0) += 1;
        *environments.entry(host.environment.clone()).or_insert(0) += 1;
        *salts.entry(host.saltversion.clone()).or_insert(0) += 1;
        *saltmaster.entry(host.saltmaster.clone()).or_insert(0) += 1;

        let filtered = filter_lines_beginning_with(&host.productname, "#");
        *products.entry(filtered).or_insert(0) += 1;

        for role in &host.roles {
            *roles.entry(role.clone()).or_insert(0) += 1;
        }

        let mut sort_roles = host.roles.to_vec();
        sort_roles.sort();
        *role_combinations.entry(render_list(&sort_roles)).or_insert(0) += 1;

        for (apptype, names) in &host.applications {
            for name in names {
                *applications.entry(format!("{}:{}", apptype, name)).or_insert(0) += 1;
            }
        }

        *os_families.entry(host.os_family.clone()).or_insert(0) += 1;
        *os.entry(host.get_full_os()).or_insert(0) += 1;
        *kernel_families.entry(host.kernel.clone()).or_insert(0) += 1;
        *kernels.entry(host.get_full_kernel()).or_insert(0) += 1;

        if host.ipv4.is_empty() {
            *ips.entry("IPv4".into()).or_insert(0) += 1;
        }

        if host.ipv6.is_empty() {
            *ips.entry("IPv6".into()).or_insert(0) += 1;
        }

        *isvirtual.entry(host.isvirtual.clone()).or_insert(0) += 1;
    }

    let header = include_str!("report.header.asciidoc");

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

    println!("Total:: {}", realms.len());
    println!("\n{}",
             render_key_value_list(&realms, "Realm".into(), "Count".into()));
    println!("");

    println!("== Environments");
    println!("Total:: {}", environments.len());
    println!("\n{}",
             render_key_value_list(&environments, "Environment".into(), "Count".into()));
    println!("");

    println!("== Salt Versions");
    println!("Total:: {}", salts.len());
    println!("\n{}",
             render_key_value_list(&salts, "Salt Version".into(), "Count".into()));
    println!("");

    println!("== Saltmaster");
    println!("Total:: {}", saltmaster.len());
    println!("\n{}",
             render_key_value_list(&saltmaster, "Master".into(), "Count".into()));
    println!("");

    println!("== Products");
    println!("Total:: {}", products.len());
    println!("\n{}",
             render_key_value_list(&products, "Product".into(), "Count".into()));
    println!("");

    println!("== Roles");
    println!("Total:: {}", roles.len());
    println!("\n{}",
             render_key_value_list(&roles, "Role".into(), "Count".into()));
    println!("");

    println!("== Role Combinations");
    println!("Total:: {}", roles.len());
    println!("\n{}",
             render_key_value_list(&role_combinations, "Combination".into(), "Count".into()));
    println!("");

    println!("== Applications");
    println!("Total:: {}", roles.len());
    println!("\n{}",
             render_key_value_list(&applications, "Application".into(), "Count".into()));
    println!("");

    println!("== OS");
    println!("=== OS Family");
    println!("Total:: {}", os_families.len());
    println!("\n{}",
             render_key_value_list(&os_families, "OS Family".into(), "Count".into()));
    println!("");

    println!("=== OS");
    println!("Total:: {}", os.len());
    println!("\n{}",
             render_key_value_list(&os, "OS".into(), "Count".into()));
    println!("");

    println!("=== Kernel Family");
    println!("Total:: {}", kernel_families.len());
    println!("\n{}",
             render_key_value_list(&kernel_families, "Kernel Family".into(), "Count".into()));
    println!("");

    println!("=== Kernel");
    println!("Total:: {}", kernels.len());
    println!("\n{}",
             render_key_value_list(&kernels, "Kernel".into(), "Count".into()));
    println!("");

    println!("=== IPs");
    println!("\n{}",
             render_key_value_list(&ips, "Version".into(), "Count".into()));
    println!("");

    println!("=== Virtual");
    println!("\n{}",
             render_key_value_list(&isvirtual, "Virtual".into(), "Count".into()));
    println!("");

    if report_hosts {
        render_report_hosts(hosts)
    }
}

fn aggregate(hosts: Map<&String, &Host>) {
    println!("{}", serde_json::to_string(&hosts).unwrap());
}

fn aggregate_roles(hosts: Map<&String, &Host>) {
    let mut agg: Map<String, u32> = Map::default();
    for host in hosts.values() {
        for role in &host.roles {
            *agg.entry(role.clone()).or_insert(0) += 1;
            *agg.entry("_total".to_string()).or_insert(0) += 1;
        }
    }

    let mut vec: Vec<Count> = Vec::default();
    for (name, count) in agg {
        vec.push(Count {
            count: count,
            name: name,
        });
    }

    println!("{}", serde_json::to_string(&vec).unwrap());
}

fn aggregate_realm(hosts: Map<&String, &Host>) {
    let mut agg: Map<String, u32> = Map::default();
    for host in hosts.values() {
        *agg.entry(host.realm.clone()).or_insert(0) += 1;
        *agg.entry("_total".to_string()).or_insert(0) += 1;
    }

    let mut vec: Vec<Count> = Vec::default();
    for (name, count) in agg {
        vec.push(Count {
            count: count,
            name: name,
        });
    }

    println!("{}", serde_json::to_string(&vec).unwrap());
}

fn aggregate_environment(hosts: Map<&String, &Host>) {
    let mut agg: Map<String, u32> = Map::default();
    for host in hosts.values() {
        *agg.entry(host.environment.clone()).or_insert(0) += 1;
        *agg.entry("_total".to_string()).or_insert(0) += 1;
    }

    let mut vec: Vec<Count> = Vec::default();
    for (name, count) in agg {
        vec.push(Count {
            count: count,
            name: name,
        });
    }

    println!("{}", serde_json::to_string(&vec).unwrap());
}

fn render_report_hosts(hosts: Map<&String, &Host>) {
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
        println!("Serialnumber:: {}", host.serialnumber);
        if !host.roles.is_empty() {
            println!("\n==== Roles\n{}", render_list(&host.roles));
        }

        if !host.applications.is_empty() {
            println!("==== Applications");
            for (apptype, apps) in &host.applications {
                println!("===== {}\n{}", apptype, render_list(&apps));
            }
        }

        println!("==== IPs");
        if let Some(ip) = host.get_reachable_ip() {
            println!("Reachable:: `{}`", ip)
        }
        println!("");

        let lookups = vec!["firewall", "firewall:admin", "firewall:backend", "firewall:frontend"];

        println!("===== Lookup");
        for lookup in lookups {
            if let Some(ip) = host.get_ip(lookup) {
                println!("{}:: `{}`", lookup, ip)
            }
        }

        println!("");

        if !host.ipv4.is_empty() {
            println!("===== IPv4\n{}", render_list(&host.ipv4));
        }

        if !host.ipv6.is_empty() {
            println!("===== IPv6\n{}", render_list(&host.ipv6));
        }

    }
}

fn render_list<A: std::fmt::Display + std::cmp::Ord>(list: &Vec<A>) -> String {
    let mut out = String::new();

    for line in list {
        out.push_str(format!("* `{}`\n", line).as_str());
    }

    out
}

fn filter_lines_beginning_with(lines: &str, beginning: &str) -> String {
    let mut out = String::new();

    for line in lines.split('\n') {
        if !line.starts_with(beginning) {
            out.push_str(line);
        }
    }

    out
}

fn render_key_value_list(list: &Map<String, u32>,
                         header_key: String,
                         header_value: String)
                         -> String {
    let mut table = String::new();

    for (key, value) in list {
        table.push_str(format!("|{}|{}\n", key, value).as_str());
    }

    format!("[cols=\"1a,1\", options=\"header\"]\n|===\n|{}|{}\n{}|===",
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
    let saltmaster = format!("Saltmaster :: `{}`",
                             value_or_default(filter.saltmaster.clone(), String::from("-")));
    let serialnumber = format!("Serialnumber:: `{}`",
                               value_or_default(filter.serialnumber.clone(), String::from("-")));
    let ipv4 = format!("IPv4 :: `{}`",
                       match (filter.ipv4.octets()[0],
                              filter.ipv4.octets()[1],
                              filter.ipv4.octets()[2],
                              filter.ipv4.octets()[3]) {
                           (0, 0, 0, 0) => "-".into(),
                           _ => format!("{}", filter.ipv4),

                       });
    let isvirtual = format!("Is Virtual:: `{}`",
                            value_or_default(filter.isvirtual.clone(), String::from("-")));

    format!("{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
            realm,
            environment,
            roles,
            id,
            id_inverse,
            os_family,
            productname,
            saltversion,
            saltmaster,
            serialnumber,
            ipv4,
            isvirtual)
}

fn value_or_default_vec(value: Vec<String>, fallback: String) -> String {
    if value.is_empty() {
        fallback
    } else {
        value.join("* {}\n")
    }
}

fn value_or_default(value: String, fallback: String) -> String {
    if value == "" { fallback } else { value }
}

fn parse_hosts_or_use_cache(folder: &Path,
                            cachefile: &Path,
                            usecache: bool,
                            cache_force_refresh: bool)
                            -> Map<String, Host> {
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

    match serde_json::from_str(&data) {
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

fn parse_hosts_from_folder(folder: &Path) -> Map<String, Host> {
    let mut hosts: Map<String, Host> = Map::new();

    let files = format!("{}/*.json", folder.display());
    for entry in glob(files.as_str()).expect("Failed to read glob pattern") {
        match entry {
            Ok(path) => {
                match file_to_string(path.as_path()) {
                    Ok(data) => {
                        match serde_json::from_str(&data) {
                            Ok(host) => {
                                let mut map: Map<String, Host> = host;
                                hosts.append(&mut map)
                            }
                            Err(_) => {
                                match serde_json::from_str(&data) {
                                    Ok(ret) => {
                                        let map: Map<String, Ret> = ret;
                                        for (id, ret) in map.into_iter() {
                                            let mut map: Map<String, Host> = Map::default();
                                            map.insert(id, ret.ret);

                                            hosts.append(&mut map)
                                        }
                                    }
                                    Err(err) => {
                                        warn!("can not parse host {:#?} from file: {}", path, err)
                                    }
                                }
                            }
                        }
                    }
                    Err(err) => warn!("can not read file: {}", err),
                }
            }
            Err(err) => warn!("can not read path from glob: {}", err),
        }
    }

    hosts
}

fn file_to_string(filepath: &Path) -> Result<String> {
    let mut s = String::new();
    let mut f = try!(File::open(filepath));
    try!(f.read_to_string(&mut s));

    Ok(s)
}

fn filter_host(host: &Host, filter: &Filter) -> bool {
    let mut filters: Vec<bool> = vec![empty_or_matching(&host.environment, &filter.environment),
                                      empty_or_matching(&host.os_family, &filter.os_family),
                                      empty_or_matching(&host.productname, &filter.productname),
                                      empty_or_matching(&host.realm, &filter.realm),
                                      empty_or_matching(&host.saltmaster, &filter.saltmaster),
                                      empty_or_matching(&host.serialnumber, &filter.serialnumber),
                                      empty_or_matching_ipv4(&host.ipv4, &filter.ipv4),
                                      empty_or_matching(&host.isvirtual, &filter.isvirtual),
                                      filter_check_applications(&host.applications, &filter)];

    match filter.roles_mode.as_str() {
        "one" => filters.push(contains_one(&host.roles, &filter.roles)),
        _ => filters.push(contains_all(&host.roles, &filter.roles)),
    }

    debug!("host filters: {:?}", filters);

    filters.iter()
        .fold(true, |acc, &x| acc && x)
}

fn filter_check_applications(applications: &Map<String, Vec<String>>, filter: &Filter) -> bool {
    if !filter.applications.is_empty() && applications.is_empty() {
        return false;
    }

    let mut filters: Vec<bool> = Vec::new();

    for (apptype, names) in applications {
        let apps = names.into_iter().map(|name| format!("{}:{}", apptype, name)).collect();
        debug!("apps: {:?}", apps);

        match filter.applications_mode.as_str() {
            "one" => filters.push(contains_one(&apps, &filter.applications)),
            _ => filters.push(contains_all(&apps, &filter.applications)),
        }
    }

    debug!("app filters: {:?}", filters);

    filters.iter()
        .fold(true, |acc, &x| acc && x)
}

fn contains_one<T: std::cmp::PartialEq>(source: &Vec<T>, search: &Vec<T>) -> bool {
    if search.is_empty() {
        return true;
    }

    for entry in search {
        if source.contains(entry) {
            return true;
        }
    }

    false
}

fn contains_all<T: std::cmp::PartialEq>(source: &Vec<T>, search: &Vec<T>) -> bool {
    if search.is_empty() {
        return true;
    }

    let mut vec = Vec::new();
    for entry in search {
        if source.contains(entry) {
            vec.push(true);
        } else {
            vec.push(false);
        }
    }

    vec.iter()
        .fold(true, |acc, &x| acc && x)
}

fn empty_or_matching_ipv4(value: &Vec<Ipv4Addr>, filter: &Ipv4Addr) -> bool {
    if filter == &Ipv4Addr::new(0, 0, 0, 0) {
        return true;
    }

    contains_one(value, &vec![filter.clone()])
}

fn empty_or_matching(value: &str, filter: &str) -> bool {
    if filter == "" {
        return true;
    }

    value == filter
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

    if warning.nosaltmaster && host.saltmaster.is_empty() {
        warn!("host {} has no saltmaster", host)
    }

    if warning.noipv6 && host.ipv6.is_empty() {
        warn!("host {} has no ipv6", host)
    }

    if warning.different_master && host.master != "salt" {
        trace!("saltmaster: {}", host.master);
        warn!("host {} has a different salt master: {}", host, host.master)
    }
}
