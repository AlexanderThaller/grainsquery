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
