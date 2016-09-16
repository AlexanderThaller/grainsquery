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
use std::collections::BTreeMap as Map;
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
use std::str::FromStr;

include!("host.rs");
include!("cache.rs");
include!("filter.rs");
include!("warn.rs");
include!("report.rs");

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
        saltmaster: String::from(matches.value_of("filter_saltmaster").unwrap_or("")),
        ipv4: Ipv4Addr::from_str(matches.value_of("filter_ip").unwrap_or(""))
            .unwrap_or(Ipv4Addr::new(0, 0, 0, 0)),
        ..Filter::new()
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
    };

    debug!("filter: {:#?}", filter);
    debug!("warning: {:#?}", warning);

    let hosts = parse_hosts_or_use_cache(&folder, cachefile, usecache, cache_force_refresh);

    debug!("Hosts Length: {}", hosts.len());

    // TODO: move this back into the filter_host function but avoid recompiling the regex for every
    // host (see example-avoid-compiling-the-same-regex-in-a-loop in the rust documentation about
    // the regex crate)
    let id_regex = Regex::new(filter.id.as_str()).unwrap();

    let hosts: Map<_, _> = hosts.iter()
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

fn render_ssh_hosts(hosts: Map<&String, &Host>, prefix: &str) {
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
