use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use rand;
use dns_lookup::lookup_host;
use log::debug;
use surge_ping::{Client, Config, PingIdentifier, PingSequence};

/// 存储发现的活跃主机
pub struct HostDiscovery {
    alive_hosts: Arc<Mutex<Vec<String>>>,
    exist_hosts: Arc<Mutex<std::collections::HashSet<String>>>,
}

impl HostDiscovery {
    pub fn new() -> Self {
        HostDiscovery {
            alive_hosts: Arc::new(Mutex::new(Vec::new())),
            exist_hosts: Arc::new(Mutex::new(std::collections::HashSet::new())),
        }
    }

    /// 解析主机名为IPv4地址
    pub fn resolve_hostname_to_ipv4(&self, hostname: &str) -> Option<Ipv4Addr> {
        // 判断输入是否已经是IPv4地址
        if let Ok(ip) = hostname.parse::<Ipv4Addr>() {
            return Some(ip);
        }

        // 使用dns_lookup库进行DNS查询
        match lookup_host(hostname) {
            Ok(ips) => {
                // 查找第一个IPv4地址
                for ip in ips {
                    match ip {
                        IpAddr::V4(ipv4) => return Some(ipv4),
                        _ => continue,
                    }
                }
                debug!("未找到主机名 {} 的IPv4地址", hostname);
                None
            },
            Err(e) => {
                debug!("无法解析主机名 {}: {}", hostname, e);
                None
            }
        }
    }

    /// 解析多个主机名为IPv4地址
    pub fn resolve_hostnames_to_ipv4(&self, hostnames: Vec<String>) -> Vec<String> {
        let mut resolved_ips = Vec::new();
        
        for hostname in hostnames {
            if let Some(ip) = self.resolve_hostname_to_ipv4(&hostname) {
                resolved_ips.push(ip.to_string());
            } else if hostname.parse::<Ipv4Addr>().is_ok() {
                // 如果输入已经是有效的IPv4地址，直接添加
                resolved_ips.push(hostname);
            }
        }
        
        resolved_ips
    }

    /// 检查主机存活状态
    pub async fn check_live(&self, hosts: Vec<String>, use_ping: bool) -> Vec<String> {
        let (tx, mut rx) = mpsc::channel(100);

        // 首先解析主机名为IPv4地址
        let resolved_hosts = self.resolve_hostnames_to_ipv4(hosts);
        debug!("已解析 {} 个主机名", resolved_hosts.len());

        // 根据参数选择检测方式
        if use_ping {
            tokio::spawn(Self::run_ping(resolved_hosts.clone(), tx));
        } else {
            tokio::spawn(Self::run_surge_ping(resolved_hosts.clone(), tx));
        }
        
        while let Some(ip) = rx.recv().await {
            let mut exist_hosts = self.exist_hosts.lock().unwrap();
            if !exist_hosts.contains(&ip) && resolved_hosts.contains(&ip) {
                exist_hosts.insert(ip.clone());
                self.alive_hosts.lock().unwrap().push(ip.clone());
                debug!("Host {} is alive", ip);
            }
        }
        // 返回存活主机列表
        self.alive_hosts.lock().unwrap().clone()
    }

    /// 使用surge-ping库实现ICMP探测
    async fn run_surge_ping( hosts: Vec<String>, tx: mpsc::Sender<String>) {
        debug!("开始使用surge-ping探测 {} 个主机", hosts.len());
        
        // 创建ICMP客户端配置
        let config = Config::default();
        let client = match Client::new(&config) {
            Ok(client) => client,
            Err(e) => {
                debug!("创建ICMP客户端失败: {}，将使用ping命令", e);
                Self::run_ping(hosts, tx).await;
                return;
            }
        };
        
        // 创建ping标识符
        let id = PingIdentifier(rand::random::<u16>());
        
        // 并发执行ping任务，批量处理以避免过多并发
        const BATCH_SIZE: usize = 10;
        for chunk in hosts.chunks(BATCH_SIZE) {
            let mut tasks = Vec::new();
            
            for host in chunk {
                let host = host.clone();
                let tx = tx.clone();
                let client = client.clone();
                
                let task = tokio::spawn(async move {
                    // 将字符串解析为IP地址
                    let addr = match host.parse::<Ipv4Addr>() {
                        Ok(ip) => IpAddr::V4(ip),
                        Err(_) => return, // 跳过无效地址
                    };
                    
                    // 创建ping流 - pinger()方法会直接返回Pinger实例
                    let mut pinger = client.pinger(addr, id).await;
                    
                    // 设置超时和重试次数
                    let timeout = Duration::from_secs(3);
                    let seq = PingSequence(1);
                    
                    // 发送ping请求并等待响应
                    match tokio::time::timeout(timeout, pinger.ping(seq, &[])).await {
                        Ok(result) => {
                            match result {
                                Ok(_) => {
                                    debug!("ICMP响应成功: {}", host);
                                    let _ = tx.send(host).await;
                                },
                                Err(e) => {
                                    debug!("ICMP响应失败: {}: {}", host, e);
                                }
                            }
                        },
                        Err(_) => {
                            debug!("ICMP请求超时: {}", host);
                        }
                    }
                });
                
                tasks.push(task);
            }
            
            // 等待当前批次的所有任务完成
            for task in tasks {
                let _ = task.await;
            }
        }
        
        debug!("所有surge-ping任务已完成");
        drop(tx);
    }

    /// 使用系统ping命令探测主机
    async fn run_ping(hosts: Vec<String>, tx: mpsc::Sender<String>) {
        debug!("开始ping {} 个主机", hosts.len());
        let hosts_clone = hosts.clone();
       

        // 使用分批处理而不是一次创建所有任务
        const BATCH_SIZE: usize = 10;
        for chunk in hosts_clone.chunks(BATCH_SIZE) {
            debug!("处理一批 {} 个主机", chunk.len());
            let mut tasks = Vec::new();
            
            for host in chunk {
                let host = host.clone();
                
                let tx = tx.clone();

                let task = tokio::spawn(async move {
                    if Self::exec_command_ping(&host).await {
                        let _ = tx.send(host).await;
                    }
                });
                tasks.push(task);
            }

            // 等待当前批次的所有ping任务完成
            for task in tasks {
                let _ = task.await;
            }
        }
        
        debug!("所有ping任务已完成");
        drop(tx);
    }

    /// 执行系统ping命令
    async fn exec_command_ping(ip: &str) -> bool {
        debug!("正在ping主机: {}", ip);
        // 过滤危险字符
        if ip.contains(|c| ";&|`$\\'\"%\n".contains(c)) {
            return false;
        }

        let output = if cfg!(target_os = "windows") {
            tokio::process::Command::new("cmd")
                .args(&["/c", &format!("ping -n 1 -w 1 {} && echo true || echo false", ip)])
                .output()
                .await
        } else {
            tokio::process::Command::new("sh")
                .args(&["-c", &format!("ping -c 1 -W 1 {} && echo true || echo false", ip)])
                .output()
                .await
        };

        match output {
            Ok(output) => {
                let output_str = String::from_utf8_lossy(&output.stdout);
                let result = output_str.contains("true") && output_str.matches(ip).count() > 2;
                debug!("Ping主机 {} 结果: {}", ip, result);
                result
            },
            Err(e) => {
                debug!("Ping主机 {} 出错: {}", ip, e);
                false
            }
        }
    }
}