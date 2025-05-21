use crate::plugins::rabbitmq_plugin::RabbitMQPlugin;
use crate::plugins::ssh_plugin::SshPlugin;
use crate::plugins::web_plugin::WebPlugin;
use crate::plugins::web_title_plugin::WebTitlePlugin;
use crate::plugins::Config;
use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashMap;
use std::time::SystemTime;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash)] // 根据需要添加派生宏
pub struct HostInfo {
    pub host: String,
    pub port: u16,
    pub url: String,
    pub infostr: Vec<String>,
}

#[derive(Debug, Clone,Serialize, Deserialize)]
pub struct ScanResult {
    pub(crate) time: SystemTime,
    pub(crate) r#type: String,
    pub(crate) target: String,
    pub(crate) status: String,
    pub(crate) details: HashMap<String, serde_json::Value>,
}

// 漏洞扫描器 ScanPlugin
#[async_trait]
pub trait ScanPlugin {
    /// 返回扫描插件的名称
    fn name(&self) -> &str;

    /// 返回插件扫描的目标端口列表
    fn ports(&self) -> &[u16];
    
    fn modes(&self) -> Vec<String>;

    /// 通过端口和指纹判断 扫描器是否支持
    fn is_support(&self,port:&u16,info:Option<String>) -> bool;
    /// 执行扫描逻辑
    async fn scan(&self, info: &mut HostInfo) -> Result<Vec<ScanResult>>;
}

pub struct PluginRegistry {
    plugins: HashMap<String, Box<dyn ScanPlugin>>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        let mut registry = Self { 
            plugins: HashMap::new(),
        };
        let config = Config::global();
        registry.register("ssh", Box::new(SshPlugin::new()));
        registry.register("rabbitmq", Box::new(RabbitMQPlugin::new()));
        registry.register("web", Box::new(WebPlugin::new(WebTitlePlugin::new().with_config(config))));
        registry
    }

    pub fn register(&mut self, name: &str, plugin: Box<dyn ScanPlugin>) {
        self.plugins.insert(name.to_string(), plugin);
    }
    
    pub fn get_by_mode(&self, mode: Option<&str>) -> Vec<&Box<dyn ScanPlugin>> {
        if let Some(mode_str) = mode {
            self.plugins.values()
                .filter(|plugin| plugin.modes().contains(&mode_str.to_string()))
                .collect()
        } else {
            self.plugins.values().collect()
        }
    }
}