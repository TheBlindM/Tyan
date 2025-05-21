use anyhow::{anyhow, Result};
use futures::stream::{self, StreamExt};
use lazy_static::lazy_static;
use regex::Captures;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use log::{debug, info};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpStream};
use tokio::time::timeout;
use crate::plugins::Config;

/// 服务识别结果
#[derive(Debug, Clone)]
pub struct ServiceInfo {
    pub name: String,                    // 服务名称
    pub banner: String,                  // 服务横幅
    pub version: String,                 // 版本信息
    pub extras: HashMap<String, String>, // 其他信息
}

impl fmt::Display for ServiceInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)?;
        if !self.version.is_empty() {
            write!(f, " {}", self.version)?;
        }
        Ok(())
    }
}

/// 探测器定义
#[derive(Debug, Clone)]
pub struct Probe {
    pub name: String,             // 探测器名称
    pub data: Vec<u8>,            // 探测数据
    pub protocol: String,         // 协议类型
    pub ports: String,            // 适用端口
    pub matchs: Vec<Match>,       // 匹配规则
    pub fallback: Option<String>, // 回退探测器
}

/// 匹配规则
#[derive(Debug, Clone)]
pub struct Match {
    pub is_soft: bool,   // 是否为软匹配，软匹配和硬匹配的区别就是是否唯一，准确度不同
    pub service: String, // 服务名称
    pub pattern: String, // 匹配模式
    pub version_info: String, // 版本信息格式
    pub pattern_compiled: Regex, // 编译后的正则表达式
}

/// 扫描结果
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub address: String,
    // 服务信息
    pub service: ServiceInfo,
}

#[derive(Debug, Clone)]
pub struct ServiceScanOptions {
    // 超时时间
    pub timeout: Duration,
    // 最大重试次数
    pub max_retries: u8,
    // 并发限制
    pub concurrent_limit: usize,
}

impl Default for ServiceScanOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(3),
            max_retries: 2,
            concurrent_limit: 50,
        }
    }
}

lazy_static! {
    // 全局探测器缓存
    static ref PROBES_CACHE: HashMap<String, Probe> = {
        let content = include_str!("nmap-service-probes.txt");
        // 解析nmap
        let probes = parse_probes_from_content(content).unwrap_or_default();

        let mut map = HashMap::new();
        for probe in probes {
            map.insert(probe.name.clone(), probe);
        }
        map
    };

    // 空探测器 - 不发送数据，只接收响应
    static ref NULL_PROBE: Option<Probe> = PROBES_CACHE.get("NULL").cloned();

    // 通用探测器 - 发送常见的请求
    static ref COMMON_PROBE: Option<Probe> = PROBES_CACHE.get("GenericLines").cloned();

    // HTTP GET 请求探测器
    static ref HTTP_GET_PROBE: Probe = Probe {
        name: "GetRequest".to_string(),
        data: b"GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n".to_vec(),
        protocol: "tcp".to_string(),
        ports: "80,81,443,1080,8000-8100,8443,9000-9100".to_string(),
        matchs: vec![],
        fallback: None,
    };
    
}

pub fn parse_probes_from_content(content: &str) -> Result<Vec<Probe>> {
    let mut probes = Vec::new();
    let mut lines: Vec<&str> = content
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty() && !line.starts_with("#"))
        .collect();

    // 验证文件格式
    if lines.is_empty() {
        return Err(anyhow!("空的探测文件"));
    }

    // 处理Exclude指令
    let mut exclude = String::new();
    if lines[0].starts_with("Exclude ") {
        exclude = lines[0][8..].to_string();
        lines.remove(0);
    }

    // 合并并分割探测器
    let content = format!("\n{}", lines.join("\n"));
    let probe_parts: Vec<&str> = content.split("\nProbe").skip(1).collect();

    // 解析每个探测器
    for probe_part in probe_parts {
        if let Ok(probe) = parse_probe(probe_part) {
            probes.push(probe);
        }
    }

    Ok(probes)
}

/// nmap 转化
fn parse_probe(content: &str) -> Result<Probe> {
    let lines: Vec<&str> = content.lines().map(|l| l.trim()).collect();
    if lines.is_empty() {
        return Err(anyhow!("空的探测器定义"));
    }
    
    let first_line = lines[0];
       let parts: Vec<&str> = first_line.splitn(3, ' ').collect();

    if parts.len() < 2 {
        return Err(anyhow!("无效的探测器定义: {}", first_line));
    }
    let re = Regex::new(r"q\|(.*?)\|")?;

    let name = parts[1].to_string();
    let protocol = parts[0].to_string();
    
    let mut data = Vec::new();
    if let Some(captures) = re.captures(&first_line) {
        if let Some(matched) = captures.get(1) {
            // matched.as_str() 包含了 \0\x0C\0\0\x10\0\0\0\0\0\0\0\0\0
            let probe_data = matched.as_str();
            data = parse_probe_data(probe_data)?;
        }
    }

    let mut ports = "1-65535".to_string();
    let mut fallback = None;
    let mut matchs = Vec::new();

    let mut i = 1;
    while i < lines.len() {
        let line = lines[i];

        if line.starts_with("match ") || line.starts_with("softmatch ") {
            // 解析匹配规则
            let is_soft = line.starts_with("softmatch ");
            let content = if is_soft { &line[10..] } else { &line[6..] };
            
            let directive = get_directive_syntax(content);

            // 分割文本获取pattern和版本信息
            let text_splited: Vec<&str> = directive.directive_str.split(&directive.delimiter).collect();
            if text_splited.is_empty() {
                return Err(anyhow!("无效的match指令格式"));
            }

            let pattern = text_splited[0];
            let version_info = text_splited[1..].join("");

            if let Ok(pattern_compiled) = Regex::new(&pattern) {
                matchs.push(Match {
                    is_soft,
                    service: directive.directive_name,
                    pattern: pattern.parse()?,
                    version_info,
                    pattern_compiled,
                });
            }
         
        } else if line.starts_with("ports ") {
            // 解析适用端口
            ports = line[6..].to_string();
        } else if line.starts_with("fallback ") {
            // 解析回退探测器
            fallback = Some(line[9..].to_string());
        }

        i += 1;
    }

    Ok(Probe {
        name,
        data,
        protocol,
        ports,
        matchs,
        fallback,
    })
}

#[derive(Debug, Clone)]
pub struct Directive {
    pub directive_name: String,
    pub flag: String,
    pub delimiter: String,
    pub directive_str: String,
}

pub fn get_directive_syntax(data: &str) -> Directive {
    log::debug!("开始解析指令语法，输入数据: {}", data);

    let mut directive = Directive {
        directive_name: String::new(),
        flag: String::new(),
        delimiter: String::new(),
        directive_str: String::new(),
    };

    // 查找第一个空格的位置
    if let Some(blank_index) = data.find(' ') {
        // 解析各个字段
        directive.directive_name = data[..blank_index].to_string();
        directive.flag = data[blank_index + 1..blank_index + 2].to_string();
        directive.delimiter = data[blank_index + 2..blank_index + 3].to_string();
        directive.directive_str = data[blank_index + 3..].to_string();

        log::debug!(
                "指令解析结果: 名称={}, 标志={}, 分隔符={}, 内容={}",
                directive.directive_name,
                directive.flag,
                directive.delimiter,
                directive.directive_str
            );
    } else {
        log::debug!("未找到空格分隔符");
    }

    directive
}
fn parse_probe_data(data: &str) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Ok(vec![]);
    }

    // 使用正则处理十六进制、八进制和结构化转义序列
    let hex_octal_struct_re = Regex::new(r"\\(x[0-9a-fA-F]{2}|[0-7]{1,3}|[aftnrv\\])")?;

    let mut result = Vec::new();
    let mut last_end = 0;

    for cap in hex_octal_struct_re.captures_iter(data) {
        let full_match = cap.get(0).unwrap();
        let escape_content = cap.get(1).unwrap();

        // 添加未匹配部分
        let unmatched_text = &data[last_end..full_match.start()];
        result.extend(unmatched_text.bytes());

        // 处理转义序列
        let escape_str = escape_content.as_str();

        if escape_str.starts_with("x") {
            // 十六进制转义
            let hex_value = &escape_str[1..];
            if let Ok(byte_val) = u8::from_str_radix(hex_value, 16) {
                result.push(byte_val);
            }
        } else if escape_str.chars().next().unwrap().is_ascii_digit() {
            // 八进制转义
            if let Ok(byte_val) = u8::from_str_radix(escape_str, 8) {
                result.push(byte_val);
            }
        } else {
            // 结构化转义
            match escape_str {
                "a" => result.push(0x07), // 响铃
                "f" => result.push(0x0c), // 换页
                "t" => result.push(0x09), // 制表符
                "n" => result.push(0x0a), // 换行
                "r" => result.push(0x0d), // 回车
                "v" => result.push(0x0b), // 垂直制表符
                "\\" => result.push(0x5c), // 反斜杠
                _ => result.push(escape_str.bytes().next().unwrap()),
            }
        }

        last_end = full_match.end();
    }

    // 添加剩余部分
    result.extend(data[last_end..].bytes());

    // 处理其他转义序列
    let other_escape_re = Regex::new(r"\\([^\\])")?;
    let mut final_result = Vec::new();
    let data_str = String::from_utf8_lossy(&result);

    let mut last_end = 0;
    for cap in other_escape_re.captures_iter(&data_str) {
        let full_match = cap.get(0).unwrap();
        let char_to_keep = cap.get(1).unwrap();

        // 添加未匹配部分
        let unmatched_text = &data_str[last_end..full_match.start()];
        final_result.extend(unmatched_text.bytes());

        // 仅保留转义后的字符
        final_result.push(char_to_keep.as_str().bytes().next().unwrap());

        last_end = full_match.end();
    }

    // 添加剩余部分
    final_result.extend(data_str[last_end..].bytes());

    if final_result.is_empty() {
        return Err(anyhow!("解码后数据为空"));
    }

    Ok(final_result)
}
pub async fn identify_service(
    addr: &str,
    port: u16,
    timeout_duration: Duration,
) -> Result<ServiceInfo> {
    let options = ServiceScanOptions {
        timeout: timeout_duration,
        ..Default::default()
    };

    identify_service_with_options(addr, port, options).await
}

pub async fn identify_service_with_options(
    addr: &str,
    port: u16,
    options: ServiceScanOptions,
) -> Result<ServiceInfo> {
    let mut retries = 0;
    let timeout_duration = options.timeout;

    // 重试机制
    while retries <= options.max_retries {
        match identify_service_internal(addr, port, timeout_duration).await
        {
            Ok(info) => return Ok(info),
            Err(e) => {
                if retries == options.max_retries {
                    return Err(e);
                }
                retries += 1;
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        }
    }

    // 默认返回
    Err(anyhow!("服务识别失败"))
}

async fn identify_service_internal(
    addr: &str,
    port: u16,
    timeout_duration: Duration,
) -> Result<ServiceInfo> {
    // 建立连接
    let mut addrs = lookup_host((addr, port)).await?;
    let socket_addr = addrs.next().ok_or_else(|| anyhow!("域名解析失败"))?;
    // let socket_addr: SocketAddr = format!("{}:{}", addr, port).parse()?;
    let connect_future = TcpStream::connect(socket_addr);
    let connect_result = timeout(timeout_duration, connect_future).await;

    let mut stream = match connect_result {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => return Err(anyhow!("连接错误: {}", e)),
        Err(_) => return Err(anyhow!("连接超时")),
    };


    let response = read_response_enhanced(&mut stream, timeout_duration).await?;


    // 如果有初始响应，尝试基础探测器
    let mut used_probes = HashSet::new();
    if !response.is_empty() {
        // 过滤掉可能为None的探测器
        info!("尝试基础探测器");
       
        let mut probes: Vec<&Probe> = Vec::new();
        if let Some(ref probe) = *NULL_PROBE {
            probes.push(probe);
        }
        if let Some(ref probe) = *COMMON_PROBE {
            probes.push(probe);
        }
        probes.push(&HTTP_GET_PROBE);

        if !probes.is_empty() {
            used_probes.insert(String::from("NULL"));
            used_probes.insert(String::from("GenericLines"));
        if let Some(info) = try_probes(
            &mut stream,
            &response,
                &probes,
            timeout_duration,
            ).await? {
            return Ok(info);
            }
        }
    }

   
    debug!("尝试端口专用探测器");
    if let Some(info) =
        process_port_map_probes(&mut stream, port, &mut used_probes, timeout_duration).await?
    {
        return Ok(info);
    }
    debug!("尝试默认探测器");
    if let Some(info) =
        process_default_probes(&mut stream, port, &mut used_probes, timeout_duration).await?
    {
        return Ok(info);
    }
    
    debug!("尝试所有探测器");
    if PROBES_CACHE.len() > used_probes.len() {
        if let Some(info) =
            try_aggressive_probes(&mut stream, port, &mut used_probes, timeout_duration).await?
        {
            return Ok(info);
        }
    }

    // 未识别，返回unknown服务
    Ok(ServiceInfo {
        name: "unknown".parse()?,
        banner: String::from_utf8_lossy(&response).to_string(),
        version: String::new(),
        extras: HashMap::new(),
    })
}

async fn read_response_enhanced(
    stream: &mut TcpStream,
    timeout_duration: Duration,
) -> Result<Vec<u8>> {
    let mut buffer = vec![0; 8192]; // 更大的缓冲区
    let mut response = Vec::new();
    let mut has_data = false;

    loop {
    // 设置非阻塞读取，最多等待timeout_duration
    let read_future = stream.read(&mut buffer);
    match timeout(timeout_duration, read_future).await {
        Ok(Ok(n)) if n > 0 => {
                has_data = true;
            response.extend_from_slice(&buffer[..n]);
                let timeout_duration = Duration::from_millis(500);
            }
            Ok(Ok(_)) => {
                //连接可能已关闭
                break;
            }
            Ok(Err(e)) => {
                if has_data {
                break;
                } else {
                    return Err(anyhow!("读取响应错误: {}", e));
                }
            }
            Err(_) => {
                // 超时，如果已有数据则返回，否则继续处理
                if has_data {
                    break;
                } else {
                    break; // 超时且没有数据，终止循环
                }
            }
        }
    }

    Ok(response)
}

async fn try_aggressive_probes(
    stream: &mut TcpStream,
    port: u16,
    used_probes: &mut HashSet<String>,
    timeout_duration: Duration,
) -> Result<Option<ServiceInfo>> {
    // 获取所有未使用的探测器
    let remaining_probes: Vec<String> = PROBES_CACHE
        .keys()
        .filter(|k| !used_probes.contains(*k))
        .cloned()
        .collect();

    for probe_name in &remaining_probes {
        used_probes.insert(probe_name.clone());

        if let Some(probe) = PROBES_CACHE.get(probe_name) {
          
            if !is_port_in_range(&probe.ports, port) {
                continue;
            }
            
            if let Err(_) = stream.write_all(&probe.data).await {
                continue;
            }
            stream.flush().await?;

          
            let response = read_response_enhanced(stream, timeout_duration).await?;
            if response.is_empty() {
                continue;
            }

            
            if let Some((info, _)) = process_matches(&response, &probe) {
                return Ok(Some(info));
            }
        }
    }

    Ok(None)
}

async fn try_probes(
    stream: &mut TcpStream,
    initial_response: &[u8],
    probes: &[&Probe],
    timeout_duration: Duration,
) -> Result<Option<ServiceInfo>> {
    // 先尝试用初始响应匹配
    for probe in probes {
        if let Some((mut info, is_hard)) = process_matches(initial_response, &probe) {
            // 如果是硬匹配，直接返回结果
            if is_hard {
                return Ok(Some(info));
            }

            // 软匹配先保留，继续尝试发送探测
            let mut soft_match = Some(info);

            // 发送探测数据
            if !probe.data.is_empty() {
                if let Ok(_) = stream.write_all(&probe.data).await {
                    stream.flush().await?;

                    // 读取响应
                    let response = read_response_enhanced(stream, timeout_duration).await?;
                    if !response.is_empty() {
                        // 尝试匹配
                        if let Some((hard_info, true)) =
                            process_matches(&response, &probe)
                        {
                           
                            return Ok(Some(hard_info));
                        }
                    }
                }
            }

            // 如果没有更好的匹配，返回软匹配
            if let Some(mut soft_info) = soft_match {
                return Ok(Some(soft_info));
            }
        }
    }

    // 如果初始匹配未成功，发送探测数据并尝试匹配
    for probe in probes {
        if !probe.data.is_empty() {
            // 发送探测数据
            if let Err(_) = stream.write_all(&probe.data).await {
                continue;
            }
            stream.flush().await?;

            // 读取响应
            let response = read_response_enhanced(stream, timeout_duration).await?;
            if response.is_empty() {
                continue;
            }

            // 尝试匹配
            if let Some((info, is_hard)) = process_matches(&response, &probe) {
                return Ok(Some(info));
            }
        }
    }

    Ok(None)
}

/// 匹配响应
fn process_matches(response: &[u8], probe: &Probe) -> Option<(ServiceInfo, bool)> {
    let matches: &[Match] = &probe.matchs;
    let response_str = String::from_utf8_lossy(response);
    let mut soft_match = None;

    // 遍历所有匹配规则
    for m in matches {
        if let Some(captures) = m.pattern_compiled.captures(&response_str) {
            println!("matche-- {:?}",m.pattern_compiled);
            println!("matchepattern-- {:?}",m.pattern);
            if !m.is_soft {
                // 硬匹配
                let extras = parse_version_info(&captures,&m.version_info);
                return Some((
                    ServiceInfo {
                        name: m.service.clone(),
                        banner: trim_banner(response),
                        version: extras.get("version").cloned().unwrap_or_default(),
                        extras,
                    },
                    true,
                ));
            } else if soft_match.is_none() {
                // 软匹配(仅保存第一个)
                soft_match = Some(m);
            }
        }
    }
    // 处理回退匹配规则
    match &probe.fallback {
        None => {}
        Some(fallback) => {
            println!("尝试回退匹配: {:?}", fallback);
            if let Some(probe) = PROBES_CACHE.get(fallback) {
                let matches: &[Match] = &probe.matchs;
                for m in matches {
                    if let Some(captures) = m.pattern_compiled.captures(&response_str) {
                        if !m.is_soft {
                            // 硬匹配
                            let extras = parse_version_info(&captures,&m.version_info);
                            return Some((
                                ServiceInfo {
                                    name: m.service.clone(),
                                    banner: trim_banner(response),
                                    version: extras.get("version").cloned().unwrap_or_default(),
                                    extras,
                                },
                                true,
                            ));
                        } else if soft_match.is_none() {
                            // 软匹配(仅保存第一个)
                            soft_match = Some(m);
                        }
                    }
                }
            }
        }
    }

    // 返回软匹配结果(如果有)
    if let Some(m) = soft_match {
        if let Some(captures) = m.pattern_compiled.captures(&response_str) {
            let extras = parse_version_info(&captures,&m.version_info);
            return Some((
                ServiceInfo {
                    name: m.service.clone(),
                    banner: trim_banner(response),
                    version: extras.get("version").cloned().unwrap_or_default(),
                    extras,
                },
                false,
            ));
        }
    }

    None
}

fn parse_version_info(captures: &Captures, version_info: &str) -> HashMap<String, String> {
    let mut extras = HashMap::new();
    let mut version_info = version_info.to_string();

    // 替换版本信息中的占位符 ($1, $2, 等)
    for i in 1..captures.len() {
        let dollar_name = format!("${}", i);
        if let Some(value) = captures.get(i) {
            version_info = version_info.replace(&dollar_name, value.as_str());
        }
    }

    // 定义解析字段的闭包函数
    let parse_field = |field_name: &str, pattern: &str| -> Option<String> {
        if !version_info.contains(pattern) {
            return None;
        }

        for delim in ["/", "|"] {
            let field_pattern = format!(r"{}\{}([^{}]*)\{}", pattern, delim, delim, delim);

            if let Some(caps) = Regex::new(&field_pattern)
                .ok()
                .and_then(|re| re.captures(&version_info))
            {
                if let Some(value) = caps.get(1) {
                    return Some(value.as_str().to_string());
                }
            }
        }
        None
    };

    // 解析各个字段
    let fields = [
        ("vendor_product", " p"),
        ("version", " v"),
        ("info", " i"),
        ("hostname", " h"),
        ("os", " o"),
        ("device_type", " d"),
    ];

    for (field, pattern) in fields {
        if let Some(value) = parse_field(field, pattern) {
            extras.insert(field.to_string(), value);
        }
    }

    // 特殊处理CPE
    if version_info.contains(" cpe:/") || version_info.contains(" cpe:|") {
        for pattern in [r"cpe:/([^/]*)", r"cpe:\|([^|]*)"] {
            if let Some(caps) = Regex::new(pattern)
                .ok()
                .and_then(|re| re.captures(&version_info))
            {
                if let Some(value) = caps.get(1) {
                    extras.insert("cpe".to_string(), value.as_str().to_string());
                    break;
                }
            }
        }
    }

    extras
}
fn trim_banner(response: &[u8]) -> String {
    let banner = String::from_utf8_lossy(response).to_string();

    // 移除横幅中的敏感信息和非打印字符
    let cleaned = banner
        .chars()
        .filter(|&c| c.is_ascii_graphic() || c.is_ascii_whitespace())
        .collect::<String>();

    // 限制横幅长度
    if cleaned.len() > 100 {
        format!("{}...", &cleaned[..97])
    } else {
        cleaned
    }
}

fn is_port_in_range(ports_spec: &str, port: u16) -> bool {
    for part in ports_spec.split(',') {
        if part.contains('-') {
            let parts: Vec<&str> = part.split('-').collect();
            if parts.len() == 2 {
                let start = parts[0].parse::<u16>().unwrap_or(0);
                let end = parts[1].parse::<u16>().unwrap_or(65535);
                if port >= start && port <= end {
                    return true;
                }
            }
        } else {
            if let Ok(p) = part.parse::<u16>() {
                if p == port {
                    return true;
                }
            }
        }
    }
    false
}

/// 服务扫描器
pub struct ServiceScanner {
    options: ServiceScanOptions,
}

impl ServiceScanner {
    /// 创建新的服务扫描器
    pub fn new(options: ServiceScanOptions) -> Self {
        Self { options }
    }

    /// 使用默认选项创建服务扫描器
    pub fn default() -> Self {
        Self {
            options: ServiceScanOptions::default(),
        }
    }

    /// 扫描单个目标
    pub async fn scan_target(&self, addr: &str, port: u16) -> Result<ServiceInfo> {
        identify_service_with_options(addr, port, self.options.clone()).await
    }

    /// 扫描多个目标
    pub async fn scan_targets(&self, targets: &[(String, u16)]) -> Vec<ScanResult> {
        batch_identify_services(targets, self.options.clone()).await
    }

    /// 按主机和端口列表扫描
    pub async fn scan_hosts(&self, hosts: &[String], ports: &[u16]) -> Vec<ScanResult> {
        let mut targets = Vec::new();
        for host in hosts {
            for &port in ports {
                targets.push((host.clone(), port));
            }
        }
        self.scan_targets(&targets).await
    }

    /// 设置选项
    pub fn with_options(mut self, options: ServiceScanOptions) -> Self {
        self.options = options;
        self
    }

    /// 设置超时
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.options.timeout = timeout;
        self
    }

    /// 设置最大重试次数
    pub fn with_max_retries(mut self, max_retries: u8) -> Self {
        self.options.max_retries = max_retries;
        self
    }

    /// 设置并发数
    pub fn with_concurrent_limit(mut self, limit: usize) -> Self {
        self.options.concurrent_limit = limit;
        self
    }
    
}

// 批量服务识别
pub async fn batch_identify_services(
    targets: &[(String, u16)],
    options: ServiceScanOptions,
) -> Vec<ScanResult> {
    let concurrent_limit = options.concurrent_limit;

    // 创建任务
    stream::iter(targets)
        .map(|(addr, port)| {
            let addr = addr.clone();
            let options = options.clone();
            async move {
                let address = format!("{}:{}", addr, port);
                match identify_service_with_options(&addr, *port, options).await {
                    Ok(service) => Some(ScanResult { address, service }),
                    Err(_) => None,
                }
            }
        })
        .buffer_unordered(concurrent_limit)
        .filter_map(|result| async { result })
        .collect::<Vec<_>>()
        .await
}

async fn process_port_map_probes(
    stream: &mut TcpStream,
    port: u16,
    used_probes: &mut HashSet<String>,
    timeout_duration: Duration,
) -> Result<Option<ServiceInfo>> {
    let config = Config::global();
    // 检查是否存在端口专用探测器
    let port_map = &config.port_map;
    if !port_map.contains_key(&port) {
        return Ok(None);
    }
    
    for probe_name in &port_map[&port] {
        // 标记已使用的探测器
        used_probes.insert(probe_name.clone());
        
        if let Some(probe) = PROBES_CACHE.get(probe_name) {
            // 发送探测数据并获取响应
            if !probe.data.is_empty() {
                if let Err(_) = stream.write_all(&probe.data).await {
                    continue;
                }
                stream.flush().await?;

                // 读取响应
                let response = read_response_enhanced(stream, timeout_duration).await?;
                if response.is_empty() {
                    continue;
                }
                debug!("response-- {:?}",String::from_utf8_lossy(&response));
                
                if let Some((info, _)) = process_matches(&response, &probe) {
                    return Ok(Some(info));
                }
                
                // match probe_name.as_str() {
                //     "GenericLines" => {
                //         if let Some(ref null_probe) = *NULL_PROBE {
                //             if let Some((info, _)) = process_matches(&response, null_probe) {
                //             return Ok(Some(info));
                //             }
                //         }
                //     }
                //     "NULL" => continue,
                //     _ => {
                //       
                //         if let Some(ref common_probe) = *COMMON_PROBE {
                //             if let Some((info, _)) = process_matches(&response, common_probe) {
                //             return Ok(Some(info));
                //             }
                //         }
                //     }
                // }
            }
        }
    }

    Ok(None)
}

async fn process_default_probes(
    stream: &mut TcpStream,
    port: u16,
    used_probes: &mut HashSet<String>,
    timeout_duration: Duration,
) -> Result<Option<ServiceInfo>> {
    let mut fail_count = 0;
    const MAX_FAILURES: usize = 10; // 最大失败次数
    let config = Config::global();
    // 检查是否存在端口专用探测器
    let default_probes = &config.default_map;
    // 遍历默认探测器列表
    for probe_name in default_probes.iter() {
        // 跳过已使用的探测器
        if used_probes.contains(probe_name) {
            continue;
        }

        // 标记为已使用
        used_probes.insert(probe_name.clone());

        // 获取探测器
        if let Some(probe) = PROBES_CACHE.get(probe_name) {
            // 发送探测数据
            if !probe.data.is_empty() {
                if let Err(_) = stream.write_all(&probe.data).await {
                    fail_count += 1;
                    if fail_count > MAX_FAILURES {
                        return Ok(None);
                    }
                    continue;
                }
                stream.flush().await?;

                // 读取响应
                let response = read_response_enhanced(stream, timeout_duration).await?;
                if response.is_empty() {
                    fail_count += 1;
                    if fail_count > MAX_FAILURES {
                        return Ok(None);
                    }
                    continue;
                }

                // 尝试匹配
                if let Some((info, _)) = process_matches(&response, &probe) {
                    return Ok(Some(info));
                }

                // 根据探测器类型进行额外检查
                // match probe_name.as_str() {
                //     "GenericLines" => {
                //         // 使用NULL探测器再次尝试
                //         if let Some(ref null_probe) = *NULL_PROBE {
                //             if let Some((info, _)) = process_matches(&response, null_probe) {
                //             return Ok(Some(info));
                //             }
                //         }
                //     }
                //     "NULL" => continue,
                //     _ => {
                //         // 使用COMMON探测器再次尝试
                //         if let Some(ref common_probe) = *COMMON_PROBE {
                //             if let Some((info, _)) = process_matches(&response, common_probe) {
                //             return Ok(Some(info));
                //             }
                //         }
                //     }
                // }
                // 
                // // 尝试使用端口映射中的其他探测器
                // if let Some(port_probes) = PORT_MAP.get(&port) {
                //     for mapped_name in port_probes {
                //         if used_probes.contains(mapped_name) {
                //             continue;
                //         }
                // 
                //         used_probes.insert(mapped_name.clone());
                // 
                //         if let Some(mapped_probe) = PROBES_CACHE.get(mapped_name) {
                //             if let Some((info, _)) =
                //                 process_matches(&response, &mapped_probe)
                //             {
                //                 return Ok(Some(info));
                //             }
                //         }
                //     }
                // }
            }
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_probe_with_complex_version_info() {
        let probe_line = "match ssl/http m|^HTTP/1.1 400 Bad Request\\r\\n.*?Server: nginx/([\\d.]+)[^\\r\\n]*?\\r\\n.*<title>400 The plain HTTP request was sent to HTTPS port</title>|s p/nginx/ v/$1/ cpe:/a:igor_sysoev:nginx:$1/";

        // 模拟解析过程
        let is_soft = false;
        let content = &probe_line[6..]; // 去掉前缀 "match "

        if let Some((service, rest)) = content.split_once(' ') {
            assert_eq!(service, "ssl/http");

            // 提取版本信息格式
            let mut pattern = rest.to_string();
            let mut version_info = String::new();

            // 版本信息标记
            let version_markers = [" p/", " v/", " i/", " h/", " o/", " d/", " cpe:/", " cpe:|"];

            if let Some(v_idx) = version_markers.iter()
                .filter_map(|marker| pattern.find(marker))
                .min() {
                // 找到了版本信息的起始位置
                version_info = pattern[v_idx..].to_string();
                pattern = pattern[..v_idx].to_string();
            }

            // 检查结果
            assert!(pattern.starts_with("m|^HTTP"));
            assert!(pattern.ends_with("|s"));
            assert!(version_info.starts_with(" p/nginx/"));
            assert!(version_info.contains(" v/$1/"));
            assert!(version_info.contains(" cpe:/a:igor_sysoev:nginx:$1/"));

            println!("Pattern: {}", pattern);
            println!("Version Info: {}", version_info);
        } else {
            panic!("Failed to split service and pattern");
        }
    }
}
