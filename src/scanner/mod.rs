use std::net::{IpAddr, Shutdown, SocketAddr, ToSocketAddrs};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, Semaphore};
use tokio::time::timeout;
use std::collections::HashSet;
use std::sync::Arc;
use std::pin::Pin;
use std::future::Future;
use std::num::NonZeroU8;
use futures::{StreamExt, stream::FuturesUnordered};
use log::{debug, info};
use crate::core::service_info::{ServiceInfo, identify_service};
use crate::scanner::socket_iterator::SocketIterator;
use anyhow::{anyhow, Result};

mod socket_iterator;

/// 端口扫描结果  
pub struct ScanResult {
    pub address: String,
    pub port: u16,
    pub service: Option<ServiceInfo>,
}

/// 端口扫描器  
pub struct PortScanner {
    ips: Vec<IpAddr>,
    ports: Vec<u16>,
    exclude_ports: Vec<u16>,
    timeout: Duration,
    batch_size: usize,
    tries: NonZeroU8,

}

impl PortScanner {
    pub fn new(ips: &[IpAddr], ports: Vec<u16>,exclude_ports: Vec<u16>,timeout_secs: u64, batch_size: usize,    tries: u8) -> Self {
        PortScanner {
            ips: ips.iter().map(ToOwned::to_owned).collect(),
            ports,
            exclude_ports,
            timeout: Duration::from_secs(timeout_secs),
            batch_size,
            tries: NonZeroU8::new(std::cmp::max(tries, 1)).unwrap(),
        }
    }

    /// 执行端口扫描  
    pub async fn run(&self) -> Vec<String> {
        let mut alive_addrs = Vec::new();
        let hosts= &self.ips;
        let ports: Vec<u16> = self
            .ports
            .iter()
            .filter(|&port| !self.exclude_ports.contains(port))
            .copied()
            .collect();
        info!("正在扫描 {} 个主机的 {} 个端口", hosts.len(), ports.len());
        
        let total_tasks = hosts.len() * ports.len();
        let mut completed_tasks = 0;

        let mut socket_iterator = SocketIterator::new(&hosts, &ports);
        let mut futures = FuturesUnordered::new();

        // 初始填充任务池
        for _ in 0..self.batch_size {
            if let Some(socket) = socket_iterator.next() {
                futures.push(self.scan_socket(socket));
            } else {
                break;
            }
        }

        // 更新进度 处理的进度
        let batch_size_log = 100;
        let mut batch_count = 0;

        while let Some(result) = futures.next().await {
            // 动态补充任务
            if let Some(socket) = socket_iterator.next() {
                futures.push(self.scan_socket(socket));
            }

            match result {
                Ok(socket) => {
                    let addr = format!("{}:{}", socket.ip(), socket.port());
                    alive_addrs.push(addr);
                }
                Err(_) => {}
            }

            completed_tasks += 1;
            batch_count += 1;

            if batch_count >= batch_size_log {
                print!("\r扫描进度: {}/{} ({}%)",
                    completed_tasks, total_tasks, 
                    (completed_tasks as f32 / total_tasks as f32 * 100.0) as u8);
                batch_count = 0;
            }
        }
        println!();
        info!("扫描完成 {}/{} (100%)", completed_tasks, total_tasks);
        alive_addrs
    }



    async fn scan_socket(
        &self,
        socket: SocketAddr
    ) -> Result<SocketAddr> {

        let tries = self.tries.get();
        for nr_try in 1..=tries {
            match self.connect(socket).await {
                Ok(mut tcp_stream) => {
                    debug!(
                        "连接成功，正在关闭流 {}",
                        &socket
                    );
                    if let Err(e) = tcp_stream.shutdown().await {
                        debug!("Shutdown stream error {}", &e);
                    }
                    debug!("尝试 {nr_try} 后成功");
                    return Ok(socket);
                }
                Err(e) => {
                    let mut error_string = e.to_string();

                    assert!(!error_string.to_lowercase().contains("too many open files"), "打开的文件过多。请减少批处理大小。默认值为5000。可尝试使用-b 2500参数。");

                    if nr_try == tries {
                        error_string.push(' ');
                        error_string.push_str(&socket.ip().to_string());
                        return Err(anyhow!(error_string));
                    }
                }
            };
        }
        unreachable!();
    }
    async fn connect(&self,socket: SocketAddr) -> Result<TcpStream> {
        match timeout(self.timeout, TcpStream::connect(socket)).await {
            Ok(Ok(stream)) => {
                Ok(stream)
            }
            Ok(Err(e)) => Err(e.into()),
            Err(_) => Err(anyhow::anyhow!("Connection timed out")),
        }
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

}