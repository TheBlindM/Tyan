use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Semaphore};
use tokio::time::timeout;
use std::collections::HashSet;
use std::sync::Arc;
use futures::{StreamExt, stream, stream::FuturesUnordered};
use log::{debug, info};
use crate::core::service_info::{ServiceInfo, identify_service};

/// 端口扫描结果  
pub struct ScanResult {
    pub address: String,
    pub port: u16,
    pub service: Option<ServiceInfo>, 
}

/// 端口扫描器  
pub struct PortScanner {
    timeout: Duration,
    thread_num: usize,
}

impl PortScanner {
    pub fn new(timeout_secs: u64, thread_num: usize) -> Self {
        PortScanner {
            timeout: Duration::from_secs(timeout_secs),
            thread_num
        }
    }

    /// 执行端口扫描  
    pub async fn scan(&self, hosts: Vec<String>, ports: Vec<u16>) -> Vec<String> {
        let mut alive_addrs = Vec::new();
        let (tx, mut rx) = mpsc::channel::<ScanResult>(1000); 
        
        info!("正在扫描 {} 个主机的 {} 个端口", hosts.len(), ports.len());
        
        let total_tasks = hosts.len() * ports.len();
        let mut completed_tasks = 0;
        
     
        let semaphore = Arc::new(Semaphore::new(self.thread_num));
        
        // 启动接收结果的任务
        let result_handler = tokio::spawn(async move {
            let mut local_alive_addrs = Vec::new();
            while let Some(result) = rx.recv().await {
                let addr = format!("{}:{}", result.address, result.port);
                local_alive_addrs.push(addr);
            }
            local_alive_addrs
        });
        

        let mut futures = FuturesUnordered::new();
        

        for host in hosts {
            for port in &ports {
                let host_clone = host.clone();
                let port_clone = *port;
                let tx_clone = tx.clone();
                let sem_clone = semaphore.clone();
                let timeout_duration =  self.timeout;
                
                let future = async move {
                    // 获取信号量许可
                    let _permit = sem_clone.acquire().await.unwrap();
                    
                    debug!("正在扫描 {}:{}", host_clone, port_clone);
                    
                    if let Ok(true) = Self::port_connect(&host_clone, port_clone, timeout_duration).await {
                        let result = ScanResult {
                            address: host_clone,
                            port: port_clone,
                            service: None,
                        };
                        let _ = tx_clone.send(result).await;
                    }
                };
                
                futures.push(future);
            }
        }
        
        // 更新进度 处理的进度
        let batch_size = 100;
        let mut batch_count = 0;
        
        while let Some(_) = futures.next().await {
            completed_tasks += 1;
            batch_count += 1;
            
            if batch_count >= batch_size {
                info!("扫描进度: {}/{} ({}%)", 
                    completed_tasks, total_tasks, 
                    (completed_tasks as f32 / total_tasks as f32 * 100.0) as u8);
                batch_count = 0;
            }
        }

     
        
        
        drop(tx);
        match result_handler.await {
            Ok(results) => {
                alive_addrs = results;
            }
            Err(e) => {
                eprintln!("[!] 结果处理任务出错: {}", e);
            }
        }
        info!("扫描完成 {}/{} (100%)", completed_tasks, total_tasks);
        alive_addrs
    }

    /// 检测单个端口连接  
    pub async fn port_connect(host: &str, port: u16, timeout_duration: Duration) -> Result<bool, std::io::Error> {
        let addr = format!("{}:{}", host, port);
        match timeout(timeout_duration, TcpStream::connect(&addr)).await {
            Ok(Ok(_)) => Ok(true),
            Ok(Err(_)) => Ok(false),
            Err(_) => Ok(false),
        }
    }

    /// 解析端口范围字符串  
    pub fn parse_ports(port_str: &str) -> Vec<u16> {
        let mut ports = Vec::new();

        for part in port_str.split(',') {
            if part.contains('-') {
                let range: Vec<&str> = part.split('-').collect();
                if range.len() == 2 {
                    if let (Ok(start), Ok(end)) = (range[0].parse::<u16>(), range[1].parse::<u16>()) {
                        ports.extend(start..=end);
                    }
                }
            } else {
                if let Ok(port) = part.parse::<u16>() {
                    ports.push(port);
                }
            }
        }

        ports
    }

    /// 排除指定端口  
    pub fn exclude_ports(ports: Vec<u16>, exclude: &str) -> Vec<u16> {
        if exclude.is_empty() {
            return ports;
        }

        let exclude_ports = Self::parse_ports(exclude);
        let exclude_set: HashSet<_> = exclude_ports.into_iter().collect();

        ports.into_iter().filter(|p| !exclude_set.contains(p)).collect()
    }
}