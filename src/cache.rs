#[derive(Debug, Serialize, Deserialize, Clone)]
struct Cache {
    gitcommit: String,
    hosts: Map<String, Host>,
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
