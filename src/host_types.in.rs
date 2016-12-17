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
}
