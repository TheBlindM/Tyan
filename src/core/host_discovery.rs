use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use rand;
use log::debug;
use surge_ping::{Client, Config, PingIdentifier, PingSequence};

/// 存储发现的活跃主机
pub struct HostDiscovery {
    alive_hosts: Arc<Mutex<Vec<IpAddr>>>,
}

impl HostDiscovery {
    pub fn new() -> Self {
        HostDiscovery {
            alive_hosts: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// 检查主机存活状态
    pub async fn check_live(&self, hosts: Vec<IpAddr>, use_ping: bool) -> Vec<IpAddr> {
        let (tx, mut rx) = mpsc::channel(100);

        debug!("开始检测 {} 个主机", hosts.len());

        // 根据参数选择检测方式
        if use_ping {
            tokio::spawn(Self::run_ping(hosts.clone(), tx));
        } else {
            tokio::spawn(Self::run_surge_ping(hosts.clone(), tx));
        }
        
        while let Some(ip) = rx.recv().await {
            if  hosts.contains(&ip) {
                self.alive_hosts.lock().unwrap().push(ip);
                debug!("Host {} is alive", ip);
            }
        }
        // 返回存活主机列表
        self.alive_hosts.lock().unwrap().clone()
    }

    /// 使用surge-ping库实现ICMP探测
    async fn run_surge_ping(hosts: Vec<IpAddr>, tx: mpsc::Sender<IpAddr>) {
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
                let host = *host;
                let tx = tx.clone();
                let client = client.clone();
                
                let task = tokio::spawn(async move {
                    // 创建ping流 - pinger()方法会直接返回Pinger实例
                    let mut pinger = client.pinger(host, id).await;
                    
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
    async fn run_ping(hosts: Vec<IpAddr>, tx: mpsc::Sender<IpAddr>) {
        debug!("开始ping {} 个主机", hosts.len());
        let hosts_clone = hosts.clone();
       

        // 使用分批处理而不是一次创建所有任务
        const BATCH_SIZE: usize = 10;
        for chunk in hosts_clone.chunks(BATCH_SIZE) {
            debug!("处理一批 {} 个主机", chunk.len());
            let mut tasks = Vec::new();
            
            for host in chunk {
                let host = *host;
                
                let tx = tx.clone();

                let task = tokio::spawn(async move {
                    if Self::exec_command_ping(&host.to_string()).await {
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