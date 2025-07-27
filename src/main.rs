use clap::{Parser, ArgAction};
use std::error::Error;
use std::time::Duration;
use std::fs;

use ipnetwork::IpNetwork;
use std::net::{Ipv4Addr, SocketAddr};
use std::ptr::null;
use std::str::FromStr;
use Tyan::core::host_discovery::HostDiscovery;
use Tyan::core::port_scanner::PortScanner;
use Tyan::core::service_info::{ServiceInfo, ServiceScanner, ServiceScanOptions};
use Tyan::core::scanner::{PluginRegistry, HostInfo};
use Tyan::core::result_storage::{ResultStorage, OutputFormat};
use log::{debug, info, warn, error, LevelFilter};
use env_logger::Builder;
use Tyan::plugins::{Config, CONFIG_GLOBAL};

#[derive(Parser)]
#[command(name = "tyan", version = "0.1", about = "一款功能强大的内网安全扫描工具", disable_help_flag(true))]
struct Cli {
    /// 目标主机 (例如: 192.168.1.1, 192.168.1.1/24, 192.168.1.1-192.168.1.100)
    #[arg(short = 'h', long = "host")]
    hosts: Option<String>,

    /// 从文件读取目标主机列表
    #[arg(long = "host-file", visible_aliases = ["hf"])]
    host_file: Option<String>,

    /// 目标端口 (例如: 80,443,8000-8100) 默认为21,22,80,443,3306,6379,8080
    #[arg(short, long)]
    port: Option<String>,

    /// 从文件读取目标端口列表
    #[arg(long = "port-file", visible_aliases = ["pf"])]
    port_file: Option<String>,

    /// 排除端口 (例如: 22,3306)
    #[arg(long = "exclude-ports")]
    exclude_ports: Option<String>,

    /// 线程数
    #[arg(short, long, default_value = "60")]
    threads: String,

    /// 超时时间(秒)
    #[arg(long, default_value = "3")]
    timeout: String,

    /// 使用系统ping代替ICMP
    #[arg(long, action = ArgAction::SetTrue)]
    ping: bool,

    /// 跳过存活检测
    #[arg(long, action = ArgAction::SetTrue)]
    no_ping: bool,
    
    /// 服务指纹识别
    #[arg(short, long, action = ArgAction::SetTrue)]
    fingerprint: bool,
    
    
    ///最大重试次数
    #[arg(long, default_value = "3")]
    retries: u8,

    /// 指定扫描模式 (例如：ModeService)
    #[arg(short = 'm', long = "mode")]
    mode: Option<String>,
    
    /// 日志级别 (debug, info, warn, error)
    #[arg(short = 'l', long = "log-level", default_value = "info")]
    log_level: String,
    
    /// 禁用暴力破解
    #[arg(long = "disable-brute", action = ArgAction::SetTrue)]
    disable_brute: bool,

    ///密码文件路径
    #[arg(long = "password-file",visible_aliases = ["pwdf"])]
    password_file: Option<String>,

    ///用户名文件路径
    #[arg(long = "username-file",visible_aliases = ["userf"])]
    username_file: Option<String>,

    ///附加用户名
    #[arg(long = "additional-usernames",visible_aliases = ["usera"])]
    additional_usernames: Option<String>,

    ///附加密码
    #[arg(long = "additional-passwords",visible_aliases = ["pwda"])]
    additional_passwords: Option<String>,

    /// 将结果导出到文件，输出格式 (json, md)，根据输出文件后缀自动判断
    #[arg(short = 'o', long = "output")]
    output_file: Option<String>,
    
    /// 显示帮助信息
    #[arg(long = "help", action = ArgAction::Help)]
    help: Option<bool>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // 显示ASCII艺术标志和版本信息
    println!("
  ______                
 /_  __/_  ______ _____ 
  / / / / / / __ `/ __ \\
 / / / /_/ / /_/ / / / /
/_/  \\__, /\\__,_/_/ /_/ 
    /____/              
    
版本 v{}", env!("CARGO_PKG_VERSION"));
    
    // 命令行参数解析
    let cli = Cli::parse();
    
    // 初始化日志系统
    let log_level = match cli.log_level.to_lowercase().as_str() {
        "debug" => LevelFilter::Debug,
        "info" => LevelFilter::Info,
        "warn" => LevelFilter::Warn,
        "error" => LevelFilter::Error,
        _ => LevelFilter::Info,
    };
    
    Builder::new()
        .filter_level(log_level)
        .format_timestamp(None)
        .init();
    

    
    // 解析参数 - 处理主机参数（支持合并）
    let mut host_parts = Vec::new();
    
    // 从命令行参数添加主机
    if let Some(hosts) = &cli.hosts {
        host_parts.push(hosts.clone());
    }
    
    // 从文件添加主机
    if let Some(host_file) = &cli.host_file {
        let file_hosts = read_hosts_from_file(host_file)?;
        host_parts.push(file_hosts);
    }
    
    if host_parts.is_empty() {
        return Err("必须指定主机参数 (-h/--host) 或主机文件 (--host-file/hf)".into());
    }

    let host_str=host_parts.join(",");

    // 处理端口参数（支持合并）
    let mut port_parts = Vec::new();
    
    // 从命令行参数添加端口
    if let Some(port) = &cli.port {
        port_parts.push(port.split(",").collect());
    }
    
    // 从文件添加端口
    if let Some(port_file) = &cli.port_file {
        let file_ports = read_ports_from_file(port_file)?;
        port_parts.push(file_ports);
    }
    
    // 如果没有指定任何端口，使用默认端口
    let port_str = if port_parts.is_empty() {
        "21,22,80,443,3306,6379,8080".to_string()
    } else {
        port_parts.join(",")
    };
    let thread_num = cli.threads.parse::<usize>().unwrap_or(60);
    let timeout = cli.timeout.parse::<u64>().unwrap_or(3);
    let use_ping = cli.ping;
    let skip_ping = cli.no_ping;
    let fingerprint = cli.fingerprint;
    let max_retries = cli.retries;
    let scan_mode = cli.mode.as_deref();
    let disable_brute = cli.disable_brute;
    let password_file = cli.password_file;
    let username_file = cli.username_file;
    let additional_passwords = cli.additional_passwords;
    let additional_usernames = cli.additional_usernames;

    let output_file = cli.output_file.clone();



    let mut config = match Config::load_default() {
        Ok(cfg) => {
            info!("成功从config.yaml加载配置");
            cfg
        },
        Err(e) => {
            error!("加载配置文件失败: {}", e);
            return Err(format!("加载配置文件失败: {}", e).into());
        }
    };

    if let Some(password_file) =password_file{
        config.set_pwds_by_file(&password_file)?;
    }
    if let Some(username_file) =username_file{
        config.set_users_by_file(&username_file)?;
    }

    if let Some(additional_passwords) = additional_passwords {
        let additional_passwords=  additional_passwords
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        config.append_pwds(additional_passwords)?;
    }


    if let Some(additional_usernames) = additional_usernames {
        let additional_usernames=  additional_usernames
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        config.append_users(additional_usernames)?;
    }

    config.set_disable_brute(disable_brute);
    config.set_brute_max_retries(max_retries);
    config.set_time_out(timeout);
    config.set_ssh_key_path(None);
    Config::init_global(config);


    
    // 默认使用JSON格式
    let mut output_format = OutputFormat::Json; 
    

     if let Some(filename) = &output_file {
        if filename.ends_with(".md") || filename.ends_with(".markdown") {
            output_format = OutputFormat::Markdown;
        }
    }

    // 创建结果存储
    let result_storage = ResultStorage::new(&host_str);
    
    // 解析主机
    let hosts = parse_ip_range(&host_str)?;
    debug!("解析到IP地址数量: {}", hosts.len());
    if hosts.len() < 10 {
        debug!("IP地址列表: {:?}", hosts);
    }

    // 主机发现
    let mut alive_hosts = hosts.clone();
    if !skip_ping && hosts.len() > 1 {
        info!("开始主机存活探测...");
        let discovery = HostDiscovery::new();
        alive_hosts = discovery.check_live(hosts, use_ping).await;
        info!("存活主机数量: {}", alive_hosts.len());
        
        result_storage.save_host_discovery_results(alive_hosts.clone());
    }

    // 端口扫描
    if !alive_hosts.is_empty() {
        info!("开始端口扫描...");
        let mut scanner = PortScanner::new(timeout, thread_num);
        
        let mut ports = PortScanner::parse_ports(&port_str);
        
        if let Some(exclude_ports_str) = &cli.exclude_ports {
            ports = PortScanner::exclude_ports(ports, exclude_ports_str);
        }
        
        let alive_addrs = scanner.scan(alive_hosts, ports).await;
        info!("开放端口数量: {}", alive_addrs.len());
        
        result_storage.save_port_scan_results(&alive_addrs);
        
        for addr in &alive_addrs {
            info!("开放: {}", addr);
        }
        
        if fingerprint && !alive_addrs.is_empty() {
            info!("开始服务指纹识别...");
            
            // 使用新的服务扫描器
            let scanner = ServiceScanner::new(
                ServiceScanOptions {
                    timeout: Duration::from_secs(timeout),
                    max_retries,
                    concurrent_limit: thread_num,
                }
            );
            
            // 解析地址和端口
            let mut targets = Vec::new();
            for addr_str in &alive_addrs {
                let parts: Vec<&str> = addr_str.split(':').collect();
                if parts.len() == 2 {
                    let ip = parts[0].to_string();
                    if let Ok(port) = parts[1].parse::<u16>() {
                        targets.push((ip, port));
                    }
                }
            }
            
            info!("开始扫描 {} 个目标...", targets.len());
            let results = scanner.scan_targets(&targets).await;
            //排除未识别的服务
            let all_service_results:Vec<_> = results.clone().into_iter().filter(|result| !result.service.name.eq("unknown")).collect();
            
            // 保存服务识别结果
            result_storage.save_service_scan_results(&all_service_results);
            
            info!("识别到的服务数量: {}", results.len());
            
            // 输出结果
            for result in results {
                let service = result.service;
                if service.name != "unknown" {
                    let mut output_str = format!("{} => {}", result.address, service.name);
                    
                    // 如果是详细模式，显示更多信息
                    if  (!service.banner.is_empty() || !service.extras.is_empty()) {
                        
                        if !service.extras.is_empty() {
                            for (k, v) in service.extras {
                                output_str = format!("{} {}: {}", output_str, k, v);
                            }
                        }
                    }
                    info!("{}", output_str);
                }
            }
        }
        
        info!("开始插件扫描...");

        let registry = PluginRegistry::new();
        let plugins = registry.get_by_mode(scan_mode);
        
        if plugins.is_empty() {
            warn!("未找到适用于当前模式的插件");
        } else {
            // 创建主机信息
            for addr_str in &alive_addrs {
                let parts: Vec<&str> = addr_str.split(':').collect();
                if parts.len() == 2 {
                    let host = parts[0].to_string();
                    let ports = parts[1].to_string();
                    let url = format!("{}:{}", host, ports);
                    
                    let mut host_info = HostInfo {
                        host,
                        port: ports.parse().unwrap(),
                        url,
                        infostr: Vec::new(),
                    };

                    let mut results =vec![];
                    for plugin in &plugins {
                        if plugin.is_support(&host_info.port,None) {
                            info!("使用插件 {} 扫描 {}", plugin.name(), addr_str);
                            let result = plugin.scan(&mut host_info).await;

                            match result {
                                Ok(result) => {
                                    results.extend(result.into_iter());
                                }
                                Err(e) => {
                                    error!("插件 {} 扫描失败: {}", plugin.name(), e);
                                }
                            }
                        }
                    }

                    result_storage.save_plugin_results(results);
                    result_storage.save_host_info(&host_info);
                    
                    // 输出插件发现的信息
                    if !host_info.infostr.is_empty() {
                        for info in &host_info.infostr {
                            info!("[+] {} - {}", addr_str, info);
                        }
                    }
                }
            }
        }
    }
    
 
    result_storage.finish_scan();

    if let Some(filename) = output_file {
        let mut final_filename = filename.clone();
        
        if !final_filename.ends_with(&format!(".{}", output_format.extension())) {
            final_filename = format!("{}.{}", final_filename, output_format.extension());
        }
        
        match result_storage.export(&final_filename, output_format) {
            Ok(_) => info!("扫描结果已保存到 {}", final_filename),
            Err(e) => error!("保存扫描结果失败: {}", e),
        }
    }

    Ok(())
}

/// 从文件读取主机列表
fn read_hosts_from_file(file_path: &str) -> Result<String, Box<dyn Error>> {
    let content = fs::read_to_string(file_path)
        .map_err(|e| format!("无法读取主机文件 {}: {}", file_path, e))?;
    
    let hosts: Vec<String> = content
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.to_string())
        .collect();
    
    if hosts.is_empty() {
        return Err(format!("主机文件 {} 为空或没有有效的主机条目", file_path).into());
    }
    
    info!("从文件 {} 读取到 {} 个主机条目", file_path, hosts.len());
    Ok(hosts.join(","))
}

/// 从文件读取端口列表
fn read_ports_from_file(file_path: &str) -> Result<String, Box<dyn Error>> {
    let content = fs::read_to_string(file_path)
        .map_err(|e| format!("无法读取端口文件 {}: {}", file_path, e))?;
    
    let ports: Vec<String> = content
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.to_string())
        .collect();
    
    if ports.is_empty() {
        return Err(format!("端口文件 {} 为空或没有有效的端口条目", file_path).into());
    }
    
    info!("从文件 {} 读取到 {} 个端口条目", file_path, ports.len());
    Ok(ports.join(","))
}

/// 解析IP范围
fn parse_ip_range(ip_str: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let mut result = Vec::new();

    // 处理逗号分隔的多个目标
    //todo 后期将ip_str 改为直接接收vec，因为hf 下直接是vec，提高效率
    if ip_str.contains(',') {
        for part in ip_str.split(',') {
            let part_result = parse_ip_range(part.trim())?;
            result.extend(part_result);
        }
        return Ok(result);
    }

    if ip_str.contains('/') {
        // 处理CIDR
        let network = IpNetwork::from_str(ip_str)?;
        if let IpNetwork::V4(network) = network {
            for ip in network.iter() {
                result.push(ip.to_string());
            }
        }
    } else if ip_str.contains('-') {
        // 处理IP范围
        let parts: Vec<&str> = ip_str.split('-').collect();
        if parts.len() == 2 {
            let start_ip = Ipv4Addr::from_str(parts[0])?;
            let end_ip = Ipv4Addr::from_str(parts[1])?;
            
            let start_u32: u32 = start_ip.into();
            let end_u32: u32 = end_ip.into();
            
            for i in start_u32..=end_u32 {
                let ip = Ipv4Addr::from(i);
                result.push(ip.to_string());
            }
        }
    } else {
        // 尝试DNS解析主机名或直接使用IP
        // 这里简单处理，直接将字符串添加到结果中
        // 注：实际生产环境可能需要进行DNS解析
        result.push(ip_str.to_string());
    }

    Ok(result)
}