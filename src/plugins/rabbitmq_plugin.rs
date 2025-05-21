use crate::core::scanner::{HostInfo, ScanPlugin, ScanResult};
use crate::plugins::Config;
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use lapin::{
    options::*,
    types::FieldTable,
    Connection,
    ConnectionProperties,
};
use log::{debug, error, info};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use tokio::net::ToSocketAddrs;
use tokio::time::timeout;


// RabbitMQ插件结构体
pub struct RabbitMQPlugin {
    name: String,
    ports: Vec<u16>,
    types: Vec<String>
}

// 尝试连接RabbitMQ服务
async fn rabbitmq_conn(
    host: &str,
    port: u16,
    user: &str,
    pass: &str,
    timeout_secs: u64,
) -> Result<bool> {
    // 构造AMQP URL
    let amqp_url = format!("amqp://{}:{}@{}:{}/", user, pass, host, port);
    debug!("尝试连接: {}", amqp_url);

    // 设置连接超时
    let conn_timeout = timeout(
        Duration::from_secs(timeout_secs),
        Connection::connect(
            &amqp_url,
            ConnectionProperties::default(),
        ),
    ).await;

    match conn_timeout {
        Ok(conn_result) => {
            match conn_result {
                Ok(connection) => {
                    // 成功连接，关闭连接并返回成功
                    let _ = connection.close(0, "").await;
                    Ok(true)
                }
                Err(e) => {
                    // 连接错误
                    if e.to_string().contains("authentication failure") || 
                       e.to_string().contains("ACCESS_REFUSED") {
                        debug!("认证失败: user={}, pass={}, error={}", user, pass, e);
                        Ok(false)
                    } else {
                        Err(anyhow!("连接错误: {}", e))
                    }
                }
            }
        }
        Err(_) => {
            // 连接超时
            Err(anyhow!("连接超时"))
        }
    }
}

// 实现ScanPlugin trait
#[async_trait]
impl ScanPlugin for RabbitMQPlugin {
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
        let host = &info.host;
        let port = info.port;
        let target = format!("{}:{}", host, port);
        let  config =Config::global();
        if config.get_disable_brute() {
            debug!("暴力破解已禁用，跳过 RabbitMQ 扫描");
            return Ok(vec![]);
        }
        
        
        
        let timeout_secs =  config.get_timeout();
        let max_retries = config.get_brute_max_retries();
        
        debug!("开始扫描 {}", target);
        debug!("尝试默认账号 guest/guest");

        // 先测试默认账号 guest/guest
        let default_user = "guest";
        let default_pass = "guest";
        
        for retry in 0..max_retries {
            if retry > 0 {
                debug!("第{}次重试默认账号: {}/{}", retry + 1, default_user, default_pass);
            }
            
            match rabbitmq_conn(host, port, default_user, default_pass, timeout_secs).await {
                Ok(true) => {
                    let success_msg = format!(
                        "RabbitMQ服务 {} 连接成功 用户名: {} 密码: {}", 
                        target, default_user, default_pass
                    );
                    info!("{}", success_msg);
                    
                    // 保存结果
                    let mut details = HashMap::new();
                    details.insert("port".to_string(), serde_json::Value::Number(serde_json::Number::from(port)));
                    details.insert("service".to_string(), serde_json::Value::String("rabbitmq".to_string()));
                    details.insert("username".to_string(), serde_json::Value::String(default_user.to_string()));
                    details.insert("password".to_string(), serde_json::Value::String(default_pass.to_string()));
                    details.insert("type".to_string(), serde_json::Value::String("weak-password".to_string()));
                    
                    let result = ScanResult {
                        time: SystemTime::now(),
                        r#type: "VULN".to_string(),
                        target: host.to_string(),
                        status: "vulnerable".to_string(),
                        details,
                    };
                    
                    return Ok(vec![result]);
                }
                Ok(false) => {
                    debug!("RabbitMQ服务 {} 默认账号认证失败", target);
                    break;
                }
                Err(e) => {
                    error!("RabbitMQ服务 {} 尝试失败 用户名: {} 密码: {} 错误: {}", 
                           target, default_user, default_pass, e);
                           
                    if should_retry(&e) {
                        if retry == max_retries - 1 {
                            continue;
                        }
                        continue;
                    }
                    break;
                }
            }
        }
        
        // 获取用户名和密码列表
        let usernames = match config.get_users_for_service("rabbitmq") {
            Some(users) => users,
            None => {
                debug!("未找到RabbitMQ用户名列表，跳过进一步扫描");
                return Ok(vec![]);
            }
        };
        
        let passwords = config.get_passwords();
        
        let total_users = usernames.len();
        let total_pass = passwords.len();
        let total = total_users * total_pass;
        let mut tried = 0;
        
        debug!("开始尝试用户名密码组合 (总用户数: {}, 总密码数: {})", total_users, total_pass);
        
        // 尝试用户名密码组合
        for user in usernames {
            for password in passwords {
                tried += 1;
                let pass = password.replace("{user}", user);
                debug!("[{}/{}] 尝试: {}:{}", tried, total, user, pass);
                
                for retry in 0..max_retries {
                    if retry > 0 {
                        debug!("第{}次重试: {}:{}", retry + 1, user, pass);
                    }
                    
                    match rabbitmq_conn(host, port, user, &pass, timeout_secs).await {
                        Ok(true) => {
                            let success_msg = format!(
                                "RabbitMQ服务 {} 连接成功 用户名: {} 密码: {}", 
                                target, user, pass
                            );
                            info!("{}", success_msg);
                            
                            // 保存结果
                            let mut details = HashMap::new();
                            details.insert("port".to_string(), serde_json::Value::Number(serde_json::Number::from(port)));
                            details.insert("service".to_string(), serde_json::Value::String("rabbitmq".to_string()));
                            details.insert("username".to_string(), serde_json::Value::String(user.to_string()));
                            details.insert("password".to_string(), serde_json::Value::String(pass.to_string()));
                            details.insert("type".to_string(), serde_json::Value::String("weak-password".to_string()));
                            
                            let result = ScanResult {
                                time: SystemTime::now(),
                                r#type: "VULN".to_string(),
                                target: host.to_string(),
                                status: "vulnerable".to_string(),
                                details,
                            };
                            
                            return Ok(vec![result]);
                        }
                        Ok(false) => {
                            debug!("认证失败: {}:{}", user, pass);
                            break;
                        }
                        Err(e) => {
                            error!("RabbitMQ服务 {} 尝试失败 用户名: {} 密码: {} 错误: {}", 
                                  target, user, pass, e);
                                  
                            if should_retry(&e) {
                                if retry == max_retries - 1 {
                                    continue;
                                }
                                continue;
                            }
                            break;
                        }
                    }
                }
            }
        }
        
        debug!("扫描完成，共尝试 {} 个组合", tried + 1);
        Ok(vec![])
    }
}

// 判断是否应该重试
fn should_retry(error: &anyhow::Error) -> bool {
    let err_str = error.to_string().to_lowercase();
    
    // 连接超时、连接重置等临时错误应该重试
    err_str.contains("timeout") || 
    err_str.contains("connection refused") || 
    err_str.contains("connection reset") || 
    err_str.contains("temporarily unavailable")
}

// 实现插件相关函数
impl RabbitMQPlugin {
    pub fn new() -> Self {
        Self {
            name: "rabbitmq".to_string(),
            ports: vec![5672], // RabbitMQ 默认端口
            types: vec!["brute".to_string()],
        }
    }
    
} 