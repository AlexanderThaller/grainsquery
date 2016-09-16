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

#[derive(Debug, Default)]
struct Warning {
    noenvironment: bool,
    norealm: bool,
    noroles: bool,
    nosaltmaster: bool,
    noipv6: bool,
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
}
