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
    saltmaster: String,
    ipv4: Ipv4Addr,
}

impl Filter {
    fn new() -> Filter {
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
            saltmaster: String::new(),
            ipv4: Ipv4Addr::new(0, 0, 0, 0),
        }
    }
}

fn filter_host(host: &Host, filter: &Filter) -> bool {
    let mut filters: Vec<bool> = vec!(
        empty_or_matching(&host.environment, &filter.environment),
        empty_or_matching(&host.os_family, &filter.os_family),
        empty_or_matching(&host.productname, &filter.productname),
        empty_or_matching(&host.realm, &filter.realm),
        empty_or_matching(&host.saltversion, &filter.saltversion),
        empty_or_matching(&host.saltmaster, &filter.saltmaster),
        empty_or_matching_ipv4(&host.ipv4, &filter.ipv4),
        );

    match filter.roles_mode.as_str() {
        "all" => filters.push(contains_all(&host.roles, &filter.roles)),
        "one" => filters.push(contains_one(&host.roles, &filter.roles)),
        _ => filters.push(contains_all(&host.roles, &filter.roles)),
    }

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

fn contains_all<T: std::cmp::PartialEq>(source: &Vec<T>, search: &Vec<T>) -> bool {
    if search.len() == 0 {
        return true;
    }

    let mut vec = Vec::new();
    for entry in search {
        if source.contains(&entry) {
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

    return contains_one(value, &vec![filter.clone()]);
}

fn empty_or_matching(value: &String, filter: &String) -> bool {
    if filter == "" {
        return true;
    }

    return value == filter;
}
