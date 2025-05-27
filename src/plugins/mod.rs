
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::{Arc, OnceLock};
use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use anyhow::Result;

pub mod ssh_plugin;
pub mod web_poc_plugin;
pub mod rabbitmq_plugin;
pub mod web_title_plugin;
pub mod web_plugin;

// SSH配置选项
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct BruteOptions {
    pub disable_brute: bool,
    pub max_retries: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleData {
    pub name: String,
    pub rule_type: String,
    pub rule: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Md5Data {
    pub name: String,
    pub md5_str: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    #[serde(rename = "Userdict")]
    pub  userdict: HashMap<String, Vec<String>>,
    #[serde(rename = "Passwords")]
    pub  passwords: Vec<String>,
    #[serde(rename = "DefaultMap")]
    pub  default_map: Vec<String>,
    #[serde(rename = "PortMap")]
    pub   port_map: HashMap<u16, Vec<String>>,
    #[serde(rename = "WebPocMap")]
    pub   web_poc_map: HashMap<String, String>,
    // 暴力破解参数
    #[serde(default)]
    pub brute_options: BruteOptions,
    #[serde(default)]
    pub timeout:u64,
    #[serde(default)]
    pub ssh_key_path: Option<String>,
    #[serde(rename = "RuleDatas", default)]
    pub rule_datas: Vec<RuleData>,
    #[serde(rename = "Md5Datas", default)]
    pub md5_datas: Vec<Md5Data>
}

#[derive(Debug, Clone)]
pub struct Draft<T: Clone + ToOwned> {
    inner: Arc<Mutex<(T, Option<T>)>>,
}
pub static CONFIG_GLOBAL: OnceCell<Config> = OnceCell::new();
impl Config {
    pub fn from_yaml<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&content)?;
        Ok(config)
    }


    pub fn init_global(config: Config) -> &'static Config {
        CONFIG_GLOBAL.get_or_init(|| {
            config
        })
    }

    pub fn global() -> &'static Config {
         CONFIG_GLOBAL.get().unwrap()
    }
    
    pub fn load_default() -> Result<Config, anyhow::Error> {
        let content = include_str!("config.yaml");
        let config: Config = serde_yaml::from_str(content)?;
        Ok(config)
    }
    
    pub fn get_userdict(&self) -> &HashMap<String, Vec<String>> {
        &self.userdict
    }
    
    pub fn get_passwords(&self) -> &Vec<String> {
        &self.passwords
    }
    
    pub fn get_default_map(&self) -> &Vec<String> {
        &self.default_map
    }
    
    pub fn get_port_map(&self) -> &HashMap<u16, Vec<String>> {
        &self.port_map
    }
    
    pub fn get_users_for_service(&self, service: &str) -> Option<&Vec<String>> {
        if self.userdict.contains_key(&String::from("customize")) {
            self.userdict.get(&String::from("customize"))
        }else {
            self.userdict.get(service)
        }
    }
    
    pub fn get_probes_for_port(&self, port: u16) -> Option<&Vec<String>> {
        self.port_map.get(&port)
    }
    
    pub fn set_disable_brute(&mut self, disable: bool) {
        self.brute_options.disable_brute = disable;
    }
    pub fn set_time_out(&mut self, timeout:u64) {
        self.timeout = timeout;
    }  
    
    pub fn set_ssh_key_path(&mut self, ssh_key_path:Option<String>) {
        self.ssh_key_path = ssh_key_path;
    }
    
    pub fn get_disable_brute(&self) -> bool {
        self.brute_options.disable_brute
    }

    pub fn get_brute_max_retries(&self) -> u8 {
        self.brute_options.max_retries
    }
    pub fn set_brute_max_retries(&mut self, retries: u8) {
        self.brute_options.max_retries=retries
    }

    pub fn get_timeout(&self) -> u64 {
        self.timeout
    }

    pub fn get_web_poc_map(&self) -> &HashMap<String, String> {
        &self.web_poc_map
    }
    
    pub fn get_brute_options(&self) -> &BruteOptions {
        &self.brute_options
    }

    pub fn set_pwds_by_file(&mut self, file:&str)->Result<()> {
        let file = File::open(file)?;
        let reader = BufReader::new(file);
        self.passwords =  reader.lines().collect::<Result<Vec<String>, _>>()?;
        Ok(())
    }

    pub fn set_users_by_file(&mut self, file:&str)->Result<()> {
        let file = File::open(file)?;
        let reader = BufReader::new(file);
        let usernames= reader.lines().collect::<Result<Vec<String>, _>>()?;
        self.userdict.insert(String::from("customize"),usernames);
        Ok(())
    }
    
    pub fn append_users(&mut self, usernames:Vec<String>)->Result<()> {
        if(!usernames.is_empty()){
            for passwords_list in self.userdict.values_mut() {
                passwords_list.extend(usernames.clone());
            }  
        }
        Ok(())
    }

    pub fn append_pwds(&mut self, pwds:Vec<String>)->Result<()> {
        self.passwords.extend(pwds.clone());
        Ok(())
    }
}