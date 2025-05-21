use async_trait::async_trait;
use crate::core::scanner::{HostInfo, ScanPlugin,ScanResult};
use anyhow::{Result, anyhow};
use log::{debug, info, warn, error};
use std::path::Path;
use std::collections::HashMap;
use std::time::SystemTime;

use crate::plugins::Config;
use crate::plugins::web_title_plugin::WebTitlePlugin;
use crate::plugins::web_poc_plugin::{load_poc, execute_poc};

// 定义Web插件结构体
pub struct WebPlugin {
    name: String,
    ports: Vec<u16>,
    types: Vec<String>,
    poc_dir: String,
    timeout_seconds: u64,
    web_title_plugin: WebTitlePlugin,
}


impl WebPlugin {
    pub fn new(web_title_plugin: WebTitlePlugin) -> Self {
        let plugin = Self {
            name: "Web".to_string(),
            // 支持常见Web端口
            ports: vec![80, 443, 8080, 8443, 8000, 8081, 8888],
            // 使用ModeWeb模式
            types: vec!["ModeWeb".to_string()],
            // 默认POC目录
            poc_dir: "src/plugins/pocs".to_string(),
            // 默认超时时间
            timeout_seconds: 5,
            web_title_plugin
        };
        plugin
    }
    
    pub fn with_poc_dir(mut self, dir: &str) -> Self {
        self.poc_dir = dir.to_string();
        self
    }
    
    pub fn with_timeout(mut self, seconds: u64) -> Self {
        self.timeout_seconds = seconds;
        self
    }
    
    fn get_poc_names_from_fingerprint(&self, fingerprints: &[String]) -> Vec<String> {
        let mut poc_names = Vec::new();
        let config = Config::global();
            let web_poc_map = config.get_web_poc_map();
        
            for fingerprint in fingerprints {
                if let Some(poc_name) = web_poc_map.get(fingerprint) {
                    debug!("为指纹 {} 找到POC: {}", fingerprint, poc_name);
                    poc_names.push(poc_name.clone());
                }
            }
        
        
        poc_names
    }
    
    // 执行指定名称的POC
    async fn execute_poc_by_name(&self, url: &str, poc_name: &str) -> Result<(bool, String)> {
        let poc_file = format!("{}/{}.yml", self.poc_dir, poc_name);
        
        if !Path::new(&poc_file).exists() {
            debug!("POC文件不存在: {}", poc_file);
            return Err(anyhow!("POC文件不存在: {}", poc_file));
        }
        
        debug!("加载POC文件: {}", poc_file);
        let poc = match load_poc(&poc_file) {
            Ok(p) => p,
            Err(e) => {
                warn!("加载POC文件失败: {}", e);
                return Err(anyhow!("加载POC文件失败: {}", e));
            }
        };
        
        debug!("执行POC: {}", poc_name);
        execute_poc(url, &poc, self.timeout_seconds).await
    }
}

#[async_trait]
impl ScanPlugin for WebPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    fn ports(&self) -> &[u16] {
        &self.ports
    }
    
    fn modes(&self) -> Vec<String> {
        self.types.clone()
    }

    fn is_support(&self, port: &u16, info: Option<String>) -> bool {
        match info {
            None => {
                self.ports.contains(port)
            }
            Some(info) => {
                true
            }
        }
    }
    
    async fn scan(&self, info: &mut HostInfo) -> Result<Vec<ScanResult>> {
        // 检查端口是否在支持列表中
        if !self.ports.contains(&info.port) {
            debug!("端口不匹配，跳过Web扫描");
            return Ok(vec![]);
        }
        
        info!("开始Web综合扫描，目标: {}:{}", info.host, info.port);
        
        // 1. 调用web_title_plugin获取指纹信息
        match self.web_title_plugin.scan(info).await {
            Ok(_) => {
                debug!("Web标题扫描完成");
            },
            Err(e) => {
                warn!("Web标题扫描失败: {}", e);
            }
        }
        

        if info.infostr.is_empty() {
            info!("未获取到Web指纹信息，结束扫描");
            return Ok(vec![]);
        }
        
        debug!("获取到Web指纹信息: {:?}", info.infostr);
        
        // 构建标准URL
        let url = if info.url.starts_with("http://") || info.url.starts_with("https://") {
            info.url.clone()
        } else {
            if info.port == 443 {
                format!("https://{}:{}", info.host, info.port)
            } else {
                format!("http://{}:{}", info.host, info.port)
            }
        };
        
        // 3. 遍历指纹，从web_poc_map中获取poc名称
        let mut executed_pocs = HashMap::new();
        let poc_names = self.get_poc_names_from_fingerprint(&info.infostr);
        
        if poc_names.is_empty() {
            info!("未找到匹配的POC，结束扫描");
            return Ok(vec![]);
        }
        
        info!("找到匹配的POC: {:?}", poc_names);

        let mut results = Vec::new();
        // 4. 执行匹配的POC
        for poc_name in poc_names {
            // 避免重复执行相同的POC
            if executed_pocs.contains_key(&poc_name) {
                continue;
            }
            
            info!("执行POC: {}", poc_name);
            
            match self.execute_poc_by_name(&url, &poc_name).await {
                Ok((is_vulnerable, vulnerability)) => {
                    executed_pocs.insert(poc_name.clone(), is_vulnerable);
                    
                    if is_vulnerable {
                        info!("发现漏洞: {} - {}", poc_name, vulnerability);
                        
                        // 构建完整的结果信息
                        let mut details = HashMap::new();
                        details.insert("port".to_string(), serde_json::Value::Number(info.port.into()));
                        details.insert("service".to_string(), serde_json::Value::String("web".to_string()));
                        details.insert("poc_name".to_string(), serde_json::Value::String(poc_name.clone()));
                        details.insert("vulnerability".to_string(), serde_json::Value::String(vulnerability.clone()));
                        
                        results.push(ScanResult {
                            time: SystemTime::now(),
                            r#type: "VULN".to_string(),
                            target: info.host.clone(),
                            status: "vulnerable".to_string(),
                            details,
                        })
                    }
                },
                Err(e) => {
                    warn!("执行POC {}失败: {}", poc_name, e);
                }
            }
        }
        
        let vulnerable_count = executed_pocs.values().filter(|&&v| v).count();
        if vulnerable_count > 0 {
            info!("Web扫描完成，发现 {} 个漏洞", vulnerable_count);
        } else {
            info!("Web扫描完成，未发现漏洞");
        }
        
        Ok(results)
    }
} 