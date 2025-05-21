use crate::core::scanner::{HostInfo, ScanPlugin};
use anyhow::{anyhow, Error, Result};
use async_trait::async_trait;
use futures::stream::{self, StreamExt};
use log::{debug, error, info, warn};
use regex::Regex;
use reqwest::Response;
use reqwest::{header::{HeaderMap, HeaderName, HeaderValue}, Client, Request};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use serde_yaml::Value as YamlValue;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use std::time::SystemTime;
use tokio::time::timeout;

// Define type aliases similar to the Go code for clarity, though not strictly necessary.
// Assuming StrMap is map[string]string
type StrMap = HashMap<String, String>;
// Assuming ListMap is map[string][]string
type ListMap = HashMap<String, Vec<String>>;
// Assuming RuleMap is map[string]Rules
type RuleMap = HashMap<String, Vec<Rule>>; // We'll define Rules below

// Placeholder for the Rules struct.
// You'll need to define its actual fields based on your Go definition or YAML structure.
#[derive(Deserialize, Debug, Clone)] // Added Clone for RuleMap usage
pub struct Rule {
    // Example fields based on your initial YAML snippet:
    #[serde(default)] // Mark fields as optional if they might be missing in YAML
    pub method: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub follow_redirects: bool,
    #[serde(default)]
    pub expression: String,
    #[serde(default)]
    pub search: String,
    #[serde(default)]
    pub timeout: u64,
}

// Placeholder for the Detail struct.
// Define its actual fields based on your Go definition or YAML structure.
#[derive(Deserialize, Debug, Default)]
pub struct Detail {
    // Example fields based on your initial YAML snippet:
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub links: Vec<String>,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub severity: String,
}

// The main Poc struct definition in Rust
#[derive(Deserialize, Debug)]
pub struct Poc {
    // Use #[serde(rename = "...")] to match the YAML field names exactly
    #[serde(rename = "name")]
    pub name: String,

    // Use #[serde(default)] if a field might be missing in the YAML
    // and you want it to default to its Default::default() value (e.g., empty HashMap).
    #[serde(rename = "set", default)]
    pub set: StrMap,

    #[serde(rename = "sets", default)]
    pub sets: ListMap,

    #[serde(rename = "rules", default)]
    pub rules: Vec<Rule>,

    #[serde(rename = "groups", default)]
    pub groups: RuleMap,

    #[serde(rename = "detail", default)]
    pub detail: Detail,
}

// 扫描结果结构体
#[derive(Serialize, Deserialize, Debug)]
pub struct ScanResult {
    pub url: String,
    pub poc_name: String,
    pub vulnerability: String,
    pub is_vulnerable: bool,
    pub details: HashMap<String, String>,
}

// DNS回连配置
#[derive(Debug, Clone)]
pub struct ReverseConfig {
    pub domain: String,
    pub token: String,
    pub api_url: String,
}

// 加载POC文件
pub fn load_poc(file_name: &str) -> Result<Poc> {
    debug!("加载POC文件: {}", file_name);
    let file = std::fs::File::open(file_name)?;
    let poc: Poc = serde_yaml::from_reader(file)?;
    Ok(poc)
}

// 加载目录下的所有POC文件
pub fn load_pocs_from_directory(dir_path: &str) -> Result<Vec<Poc>> {
    let mut pocs = Vec::new();

    if !Path::new(dir_path).exists() {
        return Err(anyhow!("POC目录不存在: {}", dir_path));
    }

    info!("从目录加载POC: {}", dir_path);

    for entry in std::fs::read_dir(dir_path)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() && path.extension().map_or(false, |ext| ext == "yml" || ext == "yaml") {
            match load_poc(path.to_str().unwrap()) {
                Ok(poc) => {
                    debug!("成功加载POC: {}", poc.name);
                    pocs.push(poc);
                },
                Err(e) => {
                    warn!("无法加载POC文件 {}: {}", path.display(), e);
                }
            }
        }
    }

    info!("共加载 {} 个POC文件", pocs.len());
    Ok(pocs)
}

// 执行POC检测
pub async fn execute_poc(url: &str, poc: &Poc, timeout_seconds: u64) -> Result<(bool, String)> {
    // 初始化变量表
    let mut variable_map = HashMap::new();

    // 基本变量设置
    variable_map.insert("target".to_string(), url.to_string());

    // 设置POC中定义的变量
    for (key, value) in &poc.set {
        if value == "newReverse()" {
            let reverse_domain = new_reverse();
            variable_map.insert(key.clone(), reverse_domain);
        } else {
            let processed_value = replace_variables(value, &variable_map);
            variable_map.insert(key.clone(), processed_value);
        }
    }

    debug!("开始执行POC: {}", poc.name);

    // 执行规则
    for (i, rule) in poc.rules.iter().enumerate() {
        debug!("执行规则 {}/{}", i+1, poc.rules.len());
        let result = execute_rule(url, rule, &mut variable_map, timeout_seconds).await?;
        if !result {
            debug!("规则执行失败，终止POC检测");
            return Ok((false, String::new()));
        }
    }

    // 处理规则组
    for (group_name, rules) in &poc.groups {
        debug!("执行规则组: {}", group_name);
        let mut success = true;

        for rule in rules {
            if !execute_rule(url, rule, &mut variable_map, timeout_seconds).await? {
                success = false;
                break;
            }
        }

        if success {
            info!("发现漏洞: {} - {}", poc.name, group_name);
            return Ok((true, group_name.clone()));
        }
    }

    Ok((false, String::new()))
}

// 评估表达式
fn evaluate_expression(expr: &str, variables: &HashMap<String, String>) -> Result<bool> {
    debug!("评估表达式: {}", expr);

    // 处理空表达式
    if expr.trim().is_empty() {
        return Ok(true);
    }

    // 处理true/false字面量
    if expr.trim() == "true" {
        return Ok(true);
    }
    if expr.trim() == "false" {
        return Ok(false);
    }

    // 处理AND逻辑操作
    if expr.contains("&&") {
        let parts: Vec<&str> = expr.split("&&").collect();
        let mut result = true;

        for part in parts {
            let part_result = evaluate_expression(part.trim(), variables)?;
            if !part_result {
                result = false;
                break;
            }
        }

        return Ok(result);
    }

    // 处理OR逻辑操作
    if expr.contains("||") {
        let parts: Vec<&str> = expr.split("||").collect();
        let mut result = false;

        for part in parts {
            let part_result = evaluate_expression(part.trim(), variables)?;
            if part_result {
                result = true;
                break;
            }
        }

        return Ok(result);
    }

    // 处理包含操作: "response.body.contains('success')"
    if expr.contains(".contains(") {
        let re = Regex::new(r"(.*?)\.contains\((.*?)\)").map_err(|e| anyhow!("无效的包含表达式: {}", e))?;
        if let Some(caps) = re.captures(expr) {
            if caps.len() > 2 {
                let container = get_variable_value(&caps[1], variables)?;
                // 移除引号
                let mut search_value = caps[2].to_string();
                search_value = search_value.trim().to_string();
                if (search_value.starts_with('\'') && search_value.ends_with('\'')) ||
                    (search_value.starts_with('"') && search_value.ends_with('"')) {
                    search_value = search_value[1..search_value.len()-1].to_string();
                }

                return Ok(container.contains(&search_value));
            }
        }
    }

    // 处理正则匹配: "response.body.matches('pattern')"
    if expr.contains(".matches(") {
        let re = Regex::new(r"(.*?)\.matches\((.*?)\)").map_err(|e| anyhow!("无效的匹配表达式: {}", e))?;
        if let Some(caps) = re.captures(expr) {
            if caps.len() > 2 {
                let text = get_variable_value(&caps[1], variables)?;
                // 移除引号
                let mut pattern = caps[2].to_string();
                pattern = pattern.trim().to_string();
                if (pattern.starts_with('\'') && pattern.ends_with('\'')) ||
                    (pattern.starts_with('"') && pattern.ends_with('"')) {
                    pattern = pattern[1..pattern.len()-1].to_string();
                }

                match Regex::new(&pattern) {
                    Ok(regex) => return Ok(regex.is_match(&text)),
                    Err(e) => return Err(anyhow!("无效的正则表达式 '{}': {}", pattern, e)),
                }
            }
        }
    }

    // 处理相等操作: "response.status==200"
    if expr.contains("==") {
        let parts: Vec<&str> = expr.split("==").collect();
        if parts.len() == 2 {
            let left = parts[0].trim();
            let right = parts[1].trim();

            let left_value = get_variable_value(left, variables)?;
            let right_value = get_variable_value(right, variables)?;

            return Ok(left_value == right_value);
        }
    }

    // 处理不等操作: "response.status!=404"
    if expr.contains("!=") {
        let parts: Vec<&str> = expr.split("!=").collect();
        if parts.len() == 2 {
            let left = parts[0].trim();
            let right = parts[1].trim();

            let left_value = get_variable_value(left, variables)?;
            let right_value = get_variable_value(right, variables)?;

            return Ok(left_value != right_value);
        }
    }

    // 处理大于操作: "response.status>200"
    if expr.contains(">") && !expr.contains(">=") {
        let parts: Vec<&str> = expr.split(">").collect();
        if parts.len() == 2 {
            let left = parts[0].trim();
            let right = parts[1].trim();

            let left_value = get_variable_value(left, variables)?;
            let right_value = get_variable_value(right, variables)?;

            // 尝试转换为数字进行比较
            if let (Ok(left_num), Ok(right_num)) = (left_value.parse::<f64>(), right_value.parse::<f64>()) {
                return Ok(left_num > right_num);
            }

            // 如果不是数字，则进行字符串比较
            return Ok(left_value > right_value);
        }
    }

    // 处理小于操作: "response.status<400"
    if expr.contains("<") && !expr.contains("<=") {
        let parts: Vec<&str> = expr.split("<").collect();
        if parts.len() == 2 {
            let left = parts[0].trim();
            let right = parts[1].trim();

            let left_value = get_variable_value(left, variables)?;
            let right_value = get_variable_value(right, variables)?;

            // 尝试转换为数字进行比较
            if let (Ok(left_num), Ok(right_num)) = (left_value.parse::<f64>(), right_value.parse::<f64>()) {
                return Ok(left_num < right_num);
            }

            // 如果不是数字，则进行字符串比较
            return Ok(left_value < right_value);
        }
    }

    // 处理大于等于操作: "response.status>=200"
    if expr.contains(">=") {
        let parts: Vec<&str> = expr.split(">=").collect();
        if parts.len() == 2 {
            let left = parts[0].trim();
            let right = parts[1].trim();

            let left_value = get_variable_value(left, variables)?;
            let right_value = get_variable_value(right, variables)?;

            // 尝试转换为数字进行比较
            if let (Ok(left_num), Ok(right_num)) = (left_value.parse::<f64>(), right_value.parse::<f64>()) {
                return Ok(left_num >= right_num);
            }

            // 如果不是数字，则进行字符串比较
            return Ok(left_value >= right_value);
        }
    }

    // 处理小于等于操作: "response.status<=400"
    if expr.contains("<=") {
        let parts: Vec<&str> = expr.split("<=").collect();
        if parts.len() == 2 {
            let left = parts[0].trim();
            let right = parts[1].trim();

            let left_value = get_variable_value(left, variables)?;
            let right_value = get_variable_value(right, variables)?;

            // 尝试转换为数字进行比较
            if let (Ok(left_num), Ok(right_num)) = (left_value.parse::<f64>(), right_value.parse::<f64>()) {
                return Ok(left_num <= right_num);
            }

            // 如果不是数字，则进行字符串比较
            return Ok(left_value <= right_value);
        }
    }

    // 处理长度操作: "response.body.length()>100"
    if expr.contains(".length()") {
        let re = Regex::new(r"(.*?)\.length\(\)(.*?)([><=]+)(.*?)").map_err(|e| anyhow!("无效的长度表达式: {}", e))?;
        if let Some(caps) = re.captures(expr) {
            if caps.len() > 4 {
                let var_name = &caps[1];
                let op = &caps[3];
                let value = &caps[4];

                let content = get_variable_value(var_name, variables)?;
                let content_length = content.len() as f64;
                let compare_value = value.trim().parse::<f64>().map_err(|e| anyhow!("无效的长度值 '{}': {}", value, e))?;

                return match op {
                    ">" => Ok(content_length > compare_value),
                    "<" => Ok(content_length < compare_value),
                    ">=" => Ok(content_length >= compare_value),
                    "<=" => Ok(content_length <= compare_value),
                    "==" => Ok(content_length == compare_value),
                    "!=" => Ok(content_length != compare_value),
                    _ => Err(anyhow!("不支持的长度比较操作符: {}", op)),
                };
            }
        }
    }

    // 处理特殊响应头比较
    if expr.contains("response.headers") {
        // 获取实际的头名称
        let re = Regex::new(r"response\.headers\.([^.]+)").map_err(|e| anyhow!("无效的响应头表达式: {}", e))?;
        if let Some(caps) = re.captures(expr) {
            let header_name = &caps[1];
            let var_name = format!("response.headers.{}", header_name);

            // 检查该头是否存在
            if expr.contains("exists()") {
                return Ok(variables.contains_key(&var_name));
            }

            // 为响应头构建新的表达式并递归求值
            // 例如: "response.headers.Content-Type.contains('application/json')"
            let new_expr = expr.replacen(&format!("response.headers.{}", header_name), &var_name, 1);
            if new_expr != expr {
                return evaluate_expression(&new_expr, variables);
            }
        }
    }

    // 如果以上所有情况都不匹配，尝试获取变量值
    if variables.contains_key(expr.trim()) {
        let val = variables.get(expr.trim()).unwrap();
        // 检查变量值是否为真值(非空、非"false"、非"0")
        return Ok(!val.is_empty() && val != "false" && val != "0");
    }

    // 无法处理的表达式
    Err(anyhow!("无法解析的表达式: {}", expr))
}

// 获取变量值，处理字面量和变量引用
fn get_variable_value(value: &str, variables: &HashMap<String, String>) -> Result<String> {
    let trimmed = value.trim();

    // 如果是引号括起来的字面量，直接返回其内容
    if (trimmed.starts_with('\'') && trimmed.ends_with('\'')) ||
        (trimmed.starts_with('"') && trimmed.ends_with('"')) {
        return Ok(trimmed[1..trimmed.len()-1].to_string());
    }

    // 如果是数字字面量，直接返回
    if trimmed.parse::<f64>().is_ok() {
        return Ok(trimmed.to_string());
    }

    // 尝试从变量表中获取值
    if let Some(val) = variables.get(trimmed) {
        return Ok(val.clone());
    }

    // 如果是复杂的变量路径，尝试解析
    if trimmed.contains('.') {
        let parts: Vec<&str> = trimmed.split('.').collect();
        let base_var = parts[0];

        if let Some(val) = variables.get(base_var) {
            // 简单情况：这是一个变量名，其中包含点
            return Ok(val.clone());
        }

        // 处理嵌套变量
        let mut full_path = String::new();
        for (i, part) in parts.iter().enumerate() {
            if i > 0 {
                full_path.push('.');
            }
            full_path.push_str(part);

            if let Some(val) = variables.get(&full_path) {
                if i == parts.len() - 1 {
                    return Ok(val.clone());
                }
            }
        }
    }

    // 如果不是变量引用，则视为字面量返回
    Ok(trimmed.to_string())
}

// 执行单个规则
async fn execute_rule(
    base_url: &str,
    rule: &Rule,
    variables: &mut HashMap<String, String>,
    timeout_seconds: u64
) -> Result<bool> {
    // 处理请求参数
    let path = replace_variables(&rule.path, variables);
    let method = if rule.method.is_empty() { "GET".to_string() } else { rule.method.clone() };

    // 处理请求头
    let mut headers = HeaderMap::new();
    for (key, value) in &rule.headers {
        let header_value = replace_variables(value, variables);
        if let (Ok(name), Ok(val)) = (
            HeaderName::from_bytes(key.as_bytes()),
            HeaderValue::from_str(&header_value)
        ) {
            headers.insert(name, val);
        }
    }

    // 处理请求体
    let body = replace_variables(&rule.body, variables);

    // 发送请求
    let timeout_duration = Duration::from_secs(timeout_seconds);
    let response = match timeout(
        timeout_duration,
        send_request(base_url, &path, &method, headers, &body, rule.follow_redirects)
    ).await {
        Ok(result) => result?,
        Err(_) => {
            warn!("请求超时: {}{}", base_url, path);
            return Ok(false);
        }
    };

    // 处理响应
    let status = response.status().as_u16();
    let resp_headers = response.headers().clone();
    let resp_body = response.text().await?;

    // 更新变量
    variables.insert("response.status".to_string(), status.to_string());
    variables.insert("response.body".to_string(), resp_body.clone());

    // 添加响应头到变量
    for (key, value) in resp_headers.iter() {
        let header_key = format!("response.headers.{}", key.as_str());
        if let Ok(val_str) = value.to_str() {
            variables.insert(header_key, val_str.to_string());
        }
    }

    // 如果有搜索表达式，执行正则匹配
    if !rule.search.is_empty() {
        let search_pattern = replace_variables(&rule.search, variables);
        if let Ok(regex) = Regex::new(&search_pattern) {
            if let Some(captures) = regex.captures(&resp_body) {
                for (i, capture) in captures.iter().enumerate() {
                    if let Some(m) = capture {
                        variables.insert(format!("search_{}", i), m.as_str().to_string());
                    }
                }
            }
        }
    }

    // 评估表达式
    if !rule.expression.is_empty() {
        let expr = replace_variables(&rule.expression, variables);
        evaluate_expression(&expr, variables)
    } else {
        // 没有表达式时默认成功
        Ok(true)
    }
}

// 发送HTTP请求
async fn send_request(
    base_url: &str,
    path: &str,
    method: &str,
    headers: HeaderMap,
    body: &str,
    follow_redirects: bool
) -> Result<Response> {
    let client_builder = Client::builder();

    // 设置重定向策略
    let client = if follow_redirects {
        client_builder.build()?
    } else {
        client_builder.redirect(reqwest::redirect::Policy::none()).build()?
    };

    let url = if path.starts_with("http://") || path.starts_with("https://") {
        path.to_string()
    } else {
        format!("{}{}", base_url, path)
    };

    debug!("发送请求: {} {}", method, url);

    let request = match method.to_uppercase().as_str() {
        "GET" => client.get(&url).headers(headers),
        "POST" => client.post(&url).headers(headers).body(body.to_string()),
        "PUT" => client.put(&url).headers(headers).body(body.to_string()),
        "DELETE" => client.delete(&url).headers(headers),
        "HEAD" => client.head(&url).headers(headers),
        "OPTIONS" => client.request(reqwest::Method::OPTIONS, &url).headers(headers),
        _ => return Err(anyhow!("不支持的HTTP方法: {}", method)),
    };

    Ok(request.send().await?)
}

// 并行执行多个POC
pub async fn check_multi_poc(
    url: &str,
    pocs: Vec<Poc>,
    workers: usize,
    timeout_seconds: u64
) -> Vec<ScanResult> {
    info!("开始对 {} 执行 {} 个POC扫描，并发数: {}", url, pocs.len(), workers);

    let url = Arc::new(url.to_string());
    let results = stream::iter(pocs.into_iter())
        .map(|poc| {
            let url_clone = Arc::clone(&url);
            async move {
                let poc_name = poc.name.clone();
                match execute_poc(&url_clone, &poc, timeout_seconds).await {
                    Ok((is_vulnerable, vul_name)) => {
                        let mut details = HashMap::new();
                        details.insert("vulnerability_name".to_string(), vul_name.clone());

                        ScanResult {
                            url: url_clone.to_string(),
                            poc_name: poc_name,
                            vulnerability: vul_name,
                            is_vulnerable,
                            details,
                        }
                    },
                    Err(e) => {
                        warn!("执行POC '{}' 失败: {}", poc_name, e);
                        let mut details = HashMap::new();
                        details.insert("error".to_string(), e.to_string());

                        ScanResult {
                            url: url_clone.to_string(),
                            poc_name,
                            vulnerability: String::new(),
                            is_vulnerable: false,
                            details,
                        }
                    }
                }
            }
        })
        .buffer_unordered(workers)
        .collect::<Vec<_>>()
        .await;

    // 过滤出有漏洞的结果
    let vulnerable_count = results.iter().filter(|r| r.is_vulnerable).count();
    info!("扫描完成: {} 个POC中发现 {} 个漏洞", results.len(), vulnerable_count);

    results
}

// 替换变量引用
fn replace_variables(text: &str, variables: &HashMap<String, String>) -> String {
    let mut result = text.to_string();
    for (name, value) in variables {
        let pattern = format!("{{{{{}}}}}", name);
        result = result.replace(&pattern, value);
    }
    result
}

// 创建DNS回连实例
fn new_reverse() -> String {
    // 这里可以实现真实的DNS回连逻辑，或者返回一个示例值
    // 在实际实现中，可能需要与外部DNS服务通信
    String::from("example.dnslog.cn")
}

// 创建默认的HTTP客户端
pub fn create_default_client() -> Result<Client> {
    Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(true) // 允许自签名证书，类似fscan的行为
        .build()
        .map_err(|e| anyhow!("创建HTTP客户端失败: {}", e))
}
// 
// // 定义WebPocPlugin结构体
// pub struct WebPocPlugin {
//     name: String,            // 插件名称
//     ports: Vec<u16>,         // 支持的端口
//     types: Vec<String>,      // 支持的模式
//     poc_dir: String,         // POC文件目录
//     timeout_seconds: u64,    // 超时时间(秒)
//     workers: usize,          // 并发工作线程数
// }
// 
// impl WebPocPlugin {
//     pub fn new() -> Self {
//         Self {
//             name: "WebPOC".to_string(),
//             // 支持常见Web端口
//             ports: vec![80, 443, 8080, 8443, 8000, 8081, 8888],
//             // 使用ModeWeb模式
//             types: vec!["ModeWeb".to_string()],
//             // 默认POC目录
//             poc_dir: "src/plugins/pocs".to_string(),
//             // 默认超时时间
//             timeout_seconds: 5,
//             // 默认工作线程数
//             workers: 10,
//         }
//     }
//     
//     // 自定义配置方法
//     pub fn with_poc_dir(mut self, dir: &str) -> Self {
//         self.poc_dir = dir.to_string();
//         self
//     }
//     
//     pub fn with_timeout(mut self, seconds: u64) -> Self {
//         self.timeout_seconds = seconds;
//         self
//     }
//     
//     pub fn with_workers(mut self, workers: usize) -> Self {
//         self.workers = workers;
//         self
//     }
// }
// 
// 
// 
// // 保存扫描结果的函数
// fn save_result(result: &WebScanResult) {
//     // 这里可以实现结果保存逻辑
//     // 可以保存到文件、数据库或通过网络发送
//     info!("发现漏洞: {:?}", result);
// }
// 
// #[async_trait]
// impl ScanPlugin for WebPocPlugin {
//     fn name(&self) -> &str {
//         &self.name
//     }
// 
//     fn ports(&self) -> &[u16] {
//         &self.ports
//     }
// 
//     fn modes(&self) -> Vec<String> {
//         self.types.clone()
//     }
// 
//     async fn scan(&self, info: &mut HostInfo) -> Result<()> {
//         // 检查端口是否在支持列表中
//         if !self.ports.contains(&info.port) {
//             info!("端口不匹配，跳过Web POC扫描");
//             return Ok(());
//         }
//         
//         
//         info!("开始Web POC扫描，目标: {}:{}", info.host, info.port);
//         
//         // 构建URL（如果不包含协议，默认使用http）
//         let url = if info.url.starts_with("http://") || info.url.starts_with("https://") {
//             info.url.clone()
//         } else {
//             if info.port == 443 {
//                 format!("https://{}:{}", info.host, info.port)
//             } else {
//                 format!("http://{}:{}", info.host, info.port)
//             }
//         };
//         
//         if !Path::new(&self.poc_dir).exists() {
//             return Err(anyhow!("POC目录不存在: {}", self.poc_dir));
//         }
//         
//         info!("从目录 {} 加载POC", self.poc_dir);
//         let pocs = match load_pocs_from_directory(&self.poc_dir) {
//             Ok(p) => p,
//             Err(e) => {
//                 warn!("加载POC失败: {}", e);
//                 return Err(anyhow!("加载POC失败: {}", e));
//             }
//         };
//         
//         if pocs.is_empty() {
//             info!("未找到有效的POC文件，扫描结束");
//             return Ok(());
//         }
//         
//         info!("加载了 {} 个POC，开始扫描", pocs.len());
//         
//         // 执行POC检测 - 直接使用异步执行，不再需要创建运行时
//         let results = check_multi_poc(&url, pocs, self.workers, self.timeout_seconds).await;
//         
//         // 处理扫描结果
//         let vulnerable_results: Vec<_> = results.iter().filter(|r| r.is_vulnerable).collect();
//         
//         if vulnerable_results.is_empty() {
//             info!("Web POC扫描完成，未发现漏洞");
//         } else {
//             info!("Web POC扫描完成，发现 {} 个漏洞", vulnerable_results.len());
//             
//             // 保存漏洞结果
//             for vuln in vulnerable_results {
//                 // 构建完整的结果信息
//                 let mut details = HashMap::new();
//                 details.insert("port".to_string(), serde_json::Value::Number(info.port.into()));
//                 details.insert("service".to_string(), serde_json::Value::String("web".to_string()));
//                 details.insert("poc_name".to_string(), serde_json::Value::String(vuln.poc_name.clone()));
//                 details.insert("vulnerability".to_string(), serde_json::Value::String(vuln.vulnerability.clone()));
//                 
//                 // 添加其他详情
//                 for (k, v) in &vuln.details {
//                     details.insert(k.clone(), serde_json::Value::String(v.clone()));
//                 }
//                 
//                 let web_result = WebScanResult {
//                     time: SystemTime::now(),
//                     r#type: "VULN".to_string(),
//                     target: info.host.clone(),
//                     status: "vulnerable".to_string(),
//                     details,
//                 };
//                 
//                 // 保存结果
//                 save_result(&web_result);
//             }
//         }
//         
//         Ok(())
//     }
// }