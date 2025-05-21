use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use serde::{Serialize, Deserialize};
use anyhow::{Result, anyhow};
use log::{info, error};

use crate::core::service_info::{ServiceInfo, ScanResult as ServiceScanResult};
use crate::core::scanner::{HostInfo, ScanResult};


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResultData {
    /// 扫描的原始目标
    pub target: String,
    
    /// 主机发现阶段的结果 - 所有存活的主机
    pub alive_hosts: Vec<String>,
    
    /// 端口扫描结果
    pub open_ports: HashMap<String, Vec<u16>>,
    
    /// 服务识别结果
    pub services: HashMap<String, ServiceInfoData>,
    
    
    pub host_infos: HashMap<String, Vec<String>>,
    
    /// 插件扫描结果 - Socket地址到插件发现信息的映射
    pub plugin_results: HashMap<String, ScanResult>,
    
    /// 扫描开始时间
    pub start_time: String,
    
    /// 扫描结束时间
    pub end_time: String,
}

/// 用于序列化的服务信息数据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfoData {
    pub name: String,
    pub banner: String,
    pub version: String,
    pub extras: HashMap<String, String>,
}

impl From<ServiceInfo> for ServiceInfoData {
    fn from(info: ServiceInfo) -> Self {
        ServiceInfoData {
            name: info.name,
            banner: info.banner,
            version: info.version,
            extras: info.extras,
        }
    }
}

/// 输出格式枚举
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OutputFormat {
    Json,
    Markdown,
}

impl OutputFormat {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "md" | "markdown" => OutputFormat::Markdown,
            _ => OutputFormat::Json,
        }
    }
    
    pub fn extension(&self) -> &'static str {
        match self {
            OutputFormat::Json => "json",
            OutputFormat::Markdown => "md",
        }
    }
}

/// 结果存储管理器 - 线程安全的单例模式
pub struct ResultStorage {
    data: Arc<Mutex<ScanResultData>>,
}

impl ResultStorage {
    pub fn new(target: &str) -> Self {
        let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        
        let data = ScanResultData {
            target: target.to_string(),
            alive_hosts: Vec::new(),
            open_ports: HashMap::new(),
            services: HashMap::new(),
            host_infos: HashMap::new(),
            plugin_results: HashMap::new(),
            start_time: now,
            end_time: String::new(),
        };
        
        ResultStorage {
            data: Arc::new(Mutex::new(data)),
        }
    }

    pub fn save_host_discovery_results(&self, hosts: Vec<String>) {
        let mut data = self.data.lock().unwrap();
        data.alive_hosts = hosts;
    }
    
    pub fn save_port_scan_results(&self, addr_list: &[String]) {
        let mut data = self.data.lock().unwrap();
        let mut open_ports: HashMap<String, Vec<u16>> = HashMap::new();
        
        for addr_str in addr_list {
            let parts: Vec<&str> = addr_str.split(':').collect();
            if parts.len() == 2 {
                let ip = parts[0].to_string();
                if let Ok(port) = parts[1].parse::<u16>() {
                    open_ports.entry(ip.clone())
                        .or_insert_with(Vec::new)
                        .push(port);
                }
            }
        }
        
        data.open_ports = open_ports;
    }
    
    pub fn save_service_scan_results(&self, results: &[ServiceScanResult]) {
        let mut data = self.data.lock().unwrap();
        
        for result in results {
            let service_data = ServiceInfoData::from(result.service.clone());
            data.services.insert(result.address.clone(), service_data);
        }
    }
    

    pub fn save_host_info(&self, host_info: &HostInfo) {
        let mut data = self.data.lock().unwrap();
        let addr = format!("{}:{}", host_info.host, host_info.port);
        
        if !host_info.infostr.is_empty() {
            data.host_infos.insert(addr, host_info.infostr.clone());
        }
    }

    pub fn save_plugin_results(&self, plugin_results: Vec<ScanResult>) {
        let mut data = self.data.lock().unwrap();
        
        for result in plugin_results {
            // 使用target字段作为键
            data.plugin_results.insert(result.target.clone(), result);
        }
    }
    
    /// 完成扫描，设置结束时间
    pub fn finish_scan(&self) {
        let mut data = self.data.lock().unwrap();
        data.end_time = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    }
    
    /// 根据指定格式导出结果
    pub fn export(&self, filename: &str, format: OutputFormat) -> Result<()> {
        match format {
            OutputFormat::Json => self.export_to_json(filename),
            OutputFormat::Markdown => self.export_to_markdown(filename),
        }
    }
    
    /// 导出结果为JSON文件
    pub fn export_to_json(&self, filename: &str) -> Result<()> {
        let data = self.data.lock().unwrap();
        let json_str = serde_json::to_string_pretty(&*data)
            .map_err(|e| anyhow!("JSON序列化失败: {}", e))?;
        
        let path = Path::new(filename);
        let mut file = File::create(path)
            .map_err(|e| anyhow!("创建文件失败: {}", e))?;
        
        file.write_all(json_str.as_bytes())
            .map_err(|e| anyhow!("写入文件失败: {}", e))?;
        
        Ok(())
    }
    
    /// 导出结果为Markdown文件
    pub fn export_to_markdown(&self, filename: &str) -> Result<()> {
        let data = self.data.lock().unwrap();
        let mut md_content = String::new();
        
        // 标题和基本信息
        md_content.push_str(&format!("# 扫描报告\n\n"));
        md_content.push_str(&format!("## 基本信息\n\n"));
        md_content.push_str(&format!("- **扫描目标**: {}\n", data.target));
        md_content.push_str(&format!("- **开始时间**: {}\n", data.start_time));
        md_content.push_str(&format!("- **结束时间**: {}\n", data.end_time));
        md_content.push_str(&format!("- **存活主机数**: {}\n", data.alive_hosts.len()));
        md_content.push_str(&format!("- **发现开放端口数**: {}\n", 
            data.open_ports.values().map(|ports| ports.len()).sum::<usize>()));
        md_content.push_str(&format!("- **识别服务数**: {}\n", data.services.len()));
        
        // 存活主机列表
        if !data.alive_hosts.is_empty() {
            md_content.push_str(&format!("\n## 存活主机列表\n\n"));
            for host in &data.alive_hosts {
                md_content.push_str(&format!("- {}\n", host));
            }
        }
        
        // 开放端口信息
        if !data.open_ports.is_empty() {
            md_content.push_str(&format!("\n## 开放端口信息\n\n"));
            md_content.push_str("| 主机 | 开放端口 |\n");
            md_content.push_str("|------|----------|\n");
            
            for (ip, ports) in &data.open_ports {
                let ports_str = ports.iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<String>>()
                    .join(", ");
                md_content.push_str(&format!("| {} | {} |\n", ip, ports_str));
            }
        }
        
        // 服务识别结果
        if !data.services.is_empty() {
            md_content.push_str(&format!("\n## 服务识别结果\n\n"));
            md_content.push_str("| 地址 | 服务名称 | 版本 | 额外信息 |\n");
            md_content.push_str("|------|---------|------|----------|\n");
            
            for (addr, service) in &data.services {
                let extras_str = service.extras.iter()
                    .map(|(k, v)| format!("{}={}", k, v))
                    .collect::<Vec<String>>()
                    .join(", ");
                
                md_content.push_str(&format!("| {} | {} | {} | {} |\n", 
                    addr, service.name, service.version, extras_str));
            }
        }
        
        // 主机信息扫描结果
        if !data.host_infos.is_empty() {
            md_content.push_str(&format!("\n## 主机信息扫描结果\n\n"));
            
            for (addr, findings) in &data.host_infos {
                md_content.push_str(&format!("### {}\n\n", addr));
                for finding in findings {
                    md_content.push_str(&format!("- {}\n", finding));
                }
                md_content.push_str("\n");
            }
        }
        
        // 插件扫描结果
        if !data.plugin_results.is_empty() {
            md_content.push_str(&format!("\n## 插件扫描结果\n\n"));
            
            for (addr, result) in &data.plugin_results {
                md_content.push_str(&format!("### {}\n\n", addr));
                
                let time_str = match SystemTime::now().duration_since(result.time) {
                    Ok(duration) => {
                        let secs = duration.as_secs();
                        format!("{} 秒前", secs)
                    },
                    Err(_) => "时间未知".to_string(),
                };
                
                md_content.push_str(&format!("**类型**: {}\n", result.r#type));
                md_content.push_str(&format!("**目标**: {}\n", result.target));
                md_content.push_str(&format!("**状态**: {}\n", result.status));
                md_content.push_str(&format!("**时间**: {}\n\n", time_str));
                
                if !result.details.is_empty() {
                    md_content.push_str("**详情**:\n\n");
                    for (key, value) in &result.details {
                        md_content.push_str(&format!("- **{}**: {}\n", key, value));
                    }
                }
                
                md_content.push_str("\n");
            }
        }
        
        let path = Path::new(filename);
        let mut file = File::create(path)
            .map_err(|e| anyhow!("创建文件失败: {}", e))?;
        
        file.write_all(md_content.as_bytes())
            .map_err(|e| anyhow!("写入文件失败: {}", e))?;
        
        Ok(())
    }
    
    pub fn get_data(&self) -> ScanResultData {
        let data = self.data.lock().unwrap();
        data.clone()
    }
} 