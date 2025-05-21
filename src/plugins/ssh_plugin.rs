use crate::core::scanner::{HostInfo, ScanPlugin, ScanResult};
use crate::plugins::Config;
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use clap::builder::TypedValueParser;
use log::{debug, error, info};
use russh::client::{self};
use russh::keys::*;
use russh::*;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
use std::time::{Duration, SystemTime};
use tokio::net::ToSocketAddrs;
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinSet;

pub struct SshPlugin {
    name: String,
    ports: Vec<u16>,
    types: Vec<String>,
}

// 创建SSH客户端处理程序
struct Client {}

#[async_trait]
impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &key::PublicKey,
    ) -> anyhow::Result<bool, Self::Error> {
        Ok(true)
    }
}

struct Session {
    session: client::Handle<Client>,
}

impl Session {
    async fn connect_with_password<A: ToSocketAddrs>(
        user: impl Into<String>,
        password: impl Into<String>,
        addrs: A,
        timeout_secs: u64,
    ) -> Result<Self> {
        let config = client::Config {
            inactivity_timeout: Some(Duration::from_secs(timeout_secs)),
            ..Default::default()
        };

        let config = Arc::new(config);
        let sh = Client {};

        let mut session = match client::connect(config, addrs, sh).await {
            Ok(session) => session,
            Err(e) => return Err(anyhow!("连接SSH服务器失败: {}", e)),
        };

        let auth_res = match session.authenticate_password(user, password).await {
            Ok(res) => res,
            Err(e) => return Err(anyhow!("密码认证过程失败: {}", e)),
        };

        if !auth_res {
            return Err(anyhow!("密码认证失败"));
        }

        Ok(Self { session })
    }

    async fn connect_with_key<P: AsRef<Path>, A: ToSocketAddrs>(
        key_path: P,
        user: impl Into<String>,
        addrs: A,
        timeout_secs: u64,
    ) -> Result<Self> {
        let key_pair = match load_secret_key(key_path, None) {
            Ok(key) => key,
            Err(e) => return Err(anyhow!("加载密钥失败: {}", e)),
        };

        let config = client::Config {
            inactivity_timeout: Some(Duration::from_secs(timeout_secs)),
            ..Default::default()
        };

        let config = Arc::new(config);
        let sh = Client {};

        let mut session = match client::connect(config, addrs, sh).await {
            Ok(session) => session,
            Err(e) => return Err(anyhow!("连接SSH服务器失败: {}", e)),
        };

        let auth_res = match session
            .authenticate_publickey(user, Arc::new(key_pair))
            .await
        {
            Ok(res) => res,
            Err(e) => return Err(anyhow!("密钥认证过程失败: {}", e)),
        };

        if !auth_res {
            return Err(anyhow!("密钥认证失败"));
        }

        Ok(Self { session })
    }

    async fn execute_command(&mut self, command: &str) -> Result<(u32, String)> {
        let mut channel = match self.session.channel_open_session().await {
            Ok(channel) => channel,
            Err(e) => return Err(anyhow!("打开会话通道失败: {}", e)),
        };

        if let Err(e) = channel.exec(true, command).await {
            return Err(anyhow!("执行命令失败: {}", e));
        }

        let mut code = None;
        let mut output = String::new();
        let mut buffer = [0u8; 4096];

        loop {
            // 等待通道上的消息
            let msg = channel.wait().await;
            if msg.is_none() {
                break;
            }

            match msg.unwrap() {
                ChannelMsg::Data { ref data } => {
                    output.push_str(&String::from_utf8_lossy(data));
                }
                ChannelMsg::ExtendedData { ref data, .. } => {
                    output.push_str(&String::from_utf8_lossy(data));
                }
                ChannelMsg::ExitStatus { exit_status } => {
                    code = Some(exit_status);
                }
                _ => {}
            }
        }

        let exit_code = code.unwrap_or(1);
        Ok((exit_code, output))
    }

    async fn close(&mut self) -> Result<()> {
        if let Err(e) = self
            .session
            .disconnect(Disconnect::ByApplication, "", "English")
            .await
        {
            return Err(anyhow!("关闭SSH连接失败: {}", e));
        }
        Ok(())
    }
}

async fn ssh_conn_async(
    host: &str,
    port: u16,
    user: &str,
    pass: &str,
    key_path: Option<&str>,
    timeout_sec: u64,
) -> Result<bool> {
    debug!("尝试SSH连接: {}:{} 用户: {}", host, port, user);
    let addr = format!("{}:{}", host, port);
    let mut session = if let Some(key_file) = key_path {
        debug!("使用密钥文件认证: {}", key_file);
        match Session::connect_with_key(key_file, user, (host, port), timeout_sec).await {
            Ok(session) => session,
            Err(e) => {
                debug!("密钥认证失败: {}", e);
                return Err(anyhow!("密钥认证失败: {}", e));
            }
        }
    } else {
        debug!("使用密码认证");
        match Session::connect_with_password(user, pass, (host, port), timeout_sec).await {
            Ok(session) => session,
            Err(e) => {
                if e.to_string().contains("认证失败") {
                    debug!("密码认证失败");
                    return Ok(false);
                }
                debug!("连接失败: {}", e);
                return Err(anyhow!("连接失败: {}", e));
            }
        }
    };

    debug!("SSH认证成功");

    // 关闭连接
    if let Err(e) = session.close().await {
        debug!("关闭SSH连接失败: {}", e);
        return Err(anyhow!("关闭SSH连接失败: {}", e));
    }

    Ok(true)
}

#[async_trait]
impl ScanPlugin for SshPlugin {
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
                debug!("端口不包含，跳过SSH扫描");
                self.ports.contains(port)
            }
            Some(info) => true,
        }
    }

    async fn scan(&self, info: &mut HostInfo) -> Result<Vec<ScanResult>> {
        let config = Config::global();
        if config.get_disable_brute() {
            info!("SSH暴力破解已禁用，跳过密码爆破");
            return Ok(vec![]);
        }

        info!("开始SSH扫描插件，目标: {}:{}", info.host, info.port);

        let max_retries = config.get_brute_max_retries();
        let target = format!("{}:{}", info.host, info.port);

        debug!("开始扫描 {}", target);

        // 从config中获取userdict和passwords
        let total_users = config.get_users_for_service("ssh").map_or(0, |v| v.len());
        let total_pass = config.get_passwords().len();
        debug!(
            "开始尝试用户名密码组合 (总用户数: {}, 总密码数: {})",
            total_users, total_pass
        );

        let total = total_users * total_pass;
        // 计数器，用于跟踪已尝试的组合数
        let tried_counter = Arc::new(AtomicUsize::new(0));
        
        // 创建用于接收成功结果的通道
        let (tx, mut rx) = mpsc::channel(1);
        
        // 并发数限制 (可以从配置读取，这里使用合理默认值)
        let max_concurrency = 20;
        let semaphore = Arc::new(Semaphore::new(max_concurrency));
        
        // 获取用户名和密码
        let users = config
            .get_users_for_service("ssh")
            .cloned()
            .unwrap_or_default();
        
        // 创建任务集合用于跟踪所有生成的任务
        let mut tasks = JoinSet::new();
        
        // 预先准备所有用户名/密码组合
        let mut combinations = Vec::new();
        for user in users {
            for pass in config.get_passwords() {
                let pass = pass.replace("{user}", &user);
                combinations.push((user.clone(), pass));
            }
        }
        
        debug!("并发执行SSH爆破，最大并发数: {}", max_concurrency);
        
        // 启动工作者任务
        for (user, pass) in combinations {
            let host = info.host.clone();
            let port = info.port;
            let key_path = config.ssh_key_path.clone();
            let timeout = config.timeout.clone();
            let target_copy = target.clone();
            let tx_clone = tx.clone();
            let sem_clone = semaphore.clone();
            let counter_clone = tried_counter.clone();
            
            // 生成任务
            tasks.spawn(async move {
                // 获取信号量许可，限制并发数
                let _permit = sem_clone.acquire().await.unwrap();
                
                // 增加已尝试计数
                let current = counter_clone.fetch_add(1, Ordering::SeqCst) + 1;
                debug!("[{}/{}] 尝试: {}:{}", current, total, user, pass);
                
                // 尝试连接
                for retry_count in 0..max_retries {
                    if retry_count > 0 {
                        debug!("第{}次重试: {}:{}", retry_count + 1, user, pass);
                    }
                    
                    let result = ssh_conn_async(
                        &host,
                        port,
                        &user,
                        &pass,
                        key_path.as_deref(),
                        timeout,
                    ).await;
                    
                    match result {
                        Ok(true) => {
                            let success_msg = format!("SSH认证成功 {} User:{} Pass:{}", target_copy, user, pass);
                            info!("{}", success_msg);
                            
                            // 创建结果详情
                            let mut details = HashMap::new();
                            details.insert(
                                "port".to_string(),
                                serde_json::Value::Number(port.into()),
                            );
                            details.insert(
                                "service".to_string(),
                                serde_json::Value::String("ssh".to_string()),
                            );
                            details.insert(
                                "username".to_string(),
                                serde_json::Value::String(user.clone()),
                            );
                            details.insert(
                                "password".to_string(),
                                serde_json::Value::String(pass.clone()),
                            );
                            details.insert(
                                "type".to_string(),
                                serde_json::Value::String("weak-password".to_string()),
                            );
                            
                            if let Some(key_path) = &key_path {
                                details.insert(
                                    "auth_type".to_string(),
                                    serde_json::Value::String("key".to_string()),
                                );
                                details.insert(
                                    "key_path".to_string(),
                                    serde_json::Value::String(key_path.clone()),
                                );
                                details.insert("password".to_string(), serde_json::Value::Null);
                            }
                            
                            let vuln_result = ScanResult {
                                time: SystemTime::now(),
                                r#type: "VULN".to_string(),
                                target: host.clone(),
                                status: "vulnerable".to_string(),
                                details,
                            };
                            
                            // 发送结果到主任务
                            let _ = tx_clone.send(Some(vuln_result)).await;
                            return;
                        }
                        Ok(false) => {
                            debug!("SSH认证失败 {} User:{} Pass:{}", target_copy, user, pass);
                            break;
                        }
                        Err(e) => {
                            let err_msg = format!(
                                "SSH连接失败 {} User:{} Pass:{} Err:{}",
                                target_copy, user, pass, e
                            );
                            debug!("{}", err_msg);
                            
                            // 检查是否需要重试
                            if should_retry(&e) {
                                if retry_count == max_retries - 1 {
                                    error!("SSH连接错误，已达到最大重试次数: {}", e);
                                    let _ = tx_clone.send(None).await;
                                    return;
                                }
                                debug!("将重试SSH连接 (原因: {})", e);
                                continue;
                            }
                            break;
                        }
                    }
                }
            });
        }
        
        // 关闭发送端，确保不会再有新的结果
        drop(tx);
        
        // 等待任务完成或接收成功结果
        tokio::select! {
            result = rx.recv() => {
                // 提前接收到成功结果
                if let Some(Some(result)) = result {
                    // 取消所有其他任务
                    tasks.abort_all();
                    info!("SSH扫描完成，发现漏洞");
                    return Ok(vec![result]);
                } else {
                    // 收到错误或通道关闭
                    tasks.abort_all();
                    return Err(anyhow!("SSH连接错误"));
                }
            }
            _ = async {
                while let Some(result) = tasks.join_next().await {
                    // 忽略任务结果，我们通过通道接收结果
                    let _ = result;
                }
            } => {
                // 所有任务已完成
                let tried = tried_counter.load(Ordering::SeqCst);
                debug!("扫描完成，共尝试 {} 个组合", tried);
                info!("SSH扫描完成，未发现漏洞");
                Ok(vec![])
            }
        }
    }
}

impl SshPlugin {
    pub fn new() -> Self {
        Self {
            name: "SSH".to_string(),
            ports: vec![22, 2222],
            types: vec![String::from("ModeService")],
        }
    }
}

// 检查是否应该重试
fn should_retry(error: &anyhow::Error) -> bool {
    let error_str = error.to_string().to_lowercase();

    // 列出需要重试的错误类型
    let should_retry = error_str.contains("timeout")
        || error_str.contains("connection reset")
        || error_str.contains("broken pipe")
        || error_str.contains("connection refused")
        || error_str.contains("network is unreachable")
        || error_str.contains("i/o error")
        || error_str.contains("handshake");

    if should_retry {
        debug!("错误需要重试: {}", error);
    } else {
        debug!("错误不需要重试: {}", error);
    }

    should_retry
}
