fn render_report(hosts: Map<&String, &Host>, filter: Filter, folder: &Path, generate_hosts: bool) {
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
    let mut realms: Map<String, u32> = Map::default();
    for (_, host) in hosts.iter() {
        *realms.entry(host.realm.clone()).or_insert(0) += 1;
    }
    println!("Total:: {}", realms.len());
    println!("\n{}",
             render_key_value_list(&realms, "Realm".into(), "Count".into()));
    println!("");

    println!("== Environments");
    let mut environments: Map<String, u32> = Map::default();
    for (_, host) in hosts.iter() {
        *environments.entry(host.environment.clone()).or_insert(0) += 1;
    }
    println!("Total:: {}", environments.len());
    println!("\n{}",
             render_key_value_list(&environments, "Environment".into(), "Count".into()));
    println!("");

    println!("== Salt Versions");
    let mut salts: Map<String, u32> = Map::default();
    for (_, host) in hosts.iter() {
        *salts.entry(host.saltversion.clone()).or_insert(0) += 1;
    }
    println!("Total:: {}", salts.len());
    println!("\n{}",
             render_key_value_list(&salts, "Salt Version".into(), "Count".into()));
    println!("");

    println!("== Saltmaster");
    let mut saltmaster: Map<String, u32> = Map::default();
    for (_, host) in hosts.iter() {
        *saltmaster.entry(host.saltmaster.clone()).or_insert(0) += 1;
    }
    println!("Total:: {}", saltmaster.len());
    println!("\n{}",
             render_key_value_list(&saltmaster, "Master".into(), "Count".into()));
    println!("");

    println!("== Products");
    let mut products: Map<String, u32> = Map::default();
    for (_, host) in hosts.iter() {
        let filtered = filter_lines_beginning_with(&host.productname, "#");
        *products.entry(filtered).or_insert(0) += 1;
    }
    println!("Total:: {}", products.len());
    println!("\n{}",
             render_key_value_list(&products, "Product".into(), "Count".into()));
    println!("");

    println!("== Roles");
    let mut roles: Map<String, u32> = Map::default();
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
    let mut os_families: Map<String, u32> = Map::default();
    for (_, host) in hosts.iter() {
        *os_families.entry(host.os_family.clone()).or_insert(0) += 1;
    }
    println!("Total:: {}", os_families.len());
    println!("\n{}",
             render_key_value_list(&os_families, "OS Family".into(), "Count".into()));
    println!("");

    println!("=== OS");
    let mut os: Map<String, u32> = Map::default();
    for (_, host) in hosts.iter() {
        *os.entry(host.get_full_os()).or_insert(0) += 1;
    }
    println!("Total:: {}", os.len());
    println!("\n{}",
             render_key_value_list(&os, "OS".into(), "Count".into()));
    println!("");

    println!("=== Kernel Family");
    let mut kernel_families: Map<String, u32> = Map::default();
    for (_, host) in hosts.iter() {
        *kernel_families.entry(host.kernel.clone()).or_insert(0) += 1;
    }
    println!("Total:: {}", kernel_families.len());
    println!("\n{}",
             render_key_value_list(&kernel_families, "Kernel Family".into(), "Count".into()));
    println!("");

    println!("=== Kernel");
    let mut kernels: Map<String, u32> = Map::default();
    for (_, host) in hosts.iter() {
        *kernels.entry(host.get_full_kernel()).or_insert(0) += 1;
    }
    println!("Total:: {}", kernels.len());
    println!("\n{}",
             render_key_value_list(&kernels, "Kernel".into(), "Count".into()));
    println!("");

    println!("=== IPs");
    let mut ips: Map<String, u32> = Map::default();
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

fn render_key_value_list(list: &Map<String, u32>,
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
    let saltmaster = format!("Saltmaster :: `{}`",
                             value_or_default(filter.saltmaster.clone(), String::from("-")));
    let ipv4 = format!("IPv4 :: `{}`",
                       match (filter.ipv4.octets()[0],
                              filter.ipv4.octets()[1],
                              filter.ipv4.octets()[2],
                              filter.ipv4.octets()[3]) {
                           (0, 0, 0, 0) => "-".into(),
                           _ => format!("{}", filter.ipv4),

                       });

    format!("{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
            realm,
            environment,
            roles,
            id,
            id_inverse,
            os_family,
            productname,
            saltversion,
            saltmaster,
            ipv4)
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
