#![crate_name = "host"]
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
// The above copyright notice and this permission notice shall be included in
// all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#[macro_use]
extern crate log;

#[macro_use]
extern crate serde_derive;

extern crate chrono;

use chrono::DateTime;
use chrono::UTC;
use std::collections::BTreeMap as Map;
use std::fmt;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::vec::Vec;

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Host {
    #[serde(default)]
    pub environment: String,
    pub id: String,
    #[serde(default)]
    pub ipv4: Vec<Ipv4Addr>,
    #[serde(default)]
    pub ipv6: Vec<Ipv6Addr>,
    #[serde(default)]
    pub kernelrelease: String,
    #[serde(default)]
    pub kernel: String,
    #[serde(default)]
    pub os_family: String,
    #[serde(default)]
    pub osrelease: String,
    #[serde(default)]
    pub os: String,
    #[serde(default)]
    pub productname: String,
    #[serde(default)]
    pub realm: String,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub saltmaster: String,
    #[serde(default)]
    pub saltversion: String,
    #[serde(default, rename = "trivago_applications")]
    pub applications: Map<String, Vec<String>>,
    #[serde(default)]
    pub master: String,
    #[serde(default)]
    pub hwaddr_interfaces: Map<String, String>,
    #[serde(default)]
    pub serialnumber: String,
    #[serde(default, rename = "virtual")]
    pub isvirtual: String,
    #[serde(default = "default_structure")]
    pub structure: String,
    #[serde(default)]
    pub role: String,
    #[serde(skip_serializing)]
    pub lastseen: Option<DateTime<UTC>>,
}

fn default_structure() -> String {
    "v1".to_string()
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.get_reachable_ip() {
            Some(ip) => write!(f, "{} ({:?})", self.id, ip),
            None => write!(f, "{} ({:?})", self.id, self.ipv4),
        }
    }
}

impl Host {
    pub fn get_full_os(&self) -> String {
        format!("{} {}", self.os, self.osrelease)
    }

    pub fn get_full_kernel(&self) -> String {
        format!("{} {}", self.kernel, self.kernelrelease)
    }

    pub fn get_ip(&self, lookup: &str) -> Option<Ipv4Addr> {
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
                                (10, 1, 5) | (10, 1, 2) | (10, 11, 2) | (10, 11, 12) |
                                (10, 21, 2) | (10, 31, 2) | (10, 51, 2) | (10, 51, 12) |
                                (192, 168, _) | (10, 1, 13) | (10, 1, 12) | (10, 1, 11) |
                                (10, 1, 10) | (10, 1, 9) | (10, 1, 8) => Some(ip),
                                _ => None,
                            }
                        }
                        "backend" => {
                            match (ip.octets()[0], ip.octets()[1], ip.octets()[2]) {
                                (10, 1, 3) | (10, 11, 3) | (10, 21, 3) | (10, 31, 3) |
                                (10, 51, 3) | (192, 168, _) | (172, _, _) => Some(ip),
                                _ => None,
                            }
                        }
                        "admin" => {
                            match (ip.octets()[0], ip.octets()[1], ip.octets()[2]) {
                                (10, 1, 6) | (10, 11, 6) | (10, 21, 6) | (10, 31, 6) |
                                (10, 51, 6) | (192, 168, _) | (172, _, _) => Some(ip),
                                _ => None,
                            }
                        }
                        _ => {
                            match (ip.octets()[0], ip.octets()[1]) {
                                (10, 1) | (10, 11) | (10, 21) | (10, 31) | (10, 51) |
                                (192, 168) | (172, _) => Some(ip),
                                _ => None,
                            }
                        }
                    }
                }
                "backbone" => {
                    match detail {
                        "admin" => {
                            match (ip.octets()[0], ip.octets()[1], ip.octets()[2]) {
                                (10, 2, 6) | (10, 12, 6) | (10, 22, 6) | (10, 32, 6) |
                                (10, 52, 6) | (192, 168, _) | (172, _, _) => Some(ip),
                                _ => None,
                            }
                        }
                        "frontend" => {
                            match (ip.octets()[0], ip.octets()[1], ip.octets()[2]) {
                                (10, 2, 5) | (10, 2, 2) | (10, 12, 2) | (10, 22, 2) |
                                (10, 52, 2) | (10, 32, 2) | (192, 168, _) | (172, _, _) => Some(ip),
                                _ => None,
                            }
                        }
                        "backend" => {
                            match (ip.octets()[0], ip.octets()[1], ip.octets()[2]) {
                                (10, 2, 3) | (10, 12, 3) | (10, 22, 3) | (10, 32, 3) |
                                (10, 52, 3) | (192, 168, _) | (172, _, _) => Some(ip),
                                _ => None,
                            }
                        }
                        _ => {
                            match (ip.octets()[0], ip.octets()[1]) {
                                (10, 2) | (10, 12) | (10, 22) | (10, 32) | (10, 52) |
                                (192, 168) | (172, _) => Some(ip),
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

    pub fn get_reachable_ip(&self) -> Option<Ipv4Addr> {
        let lookups = vec!["firewall:frontend", "firewall:admin", "firewall:backend", "firewall"];

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
