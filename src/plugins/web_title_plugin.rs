use crate::core::scanner::{HostInfo, ScanPlugin, ScanResult};
use crate::plugins::Config;
use crate::plugins::{Md5Data, RuleData};
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use log::{debug, error, info};
use regex::Regex;
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue},
    redirect::Policy,
    Client, ClientBuilder, Response,
};
use std::collections::HashMap;
use std::net::ToSocketAddrs;
use std::str;
use std::sync::Arc;
use std::time::Instant;
use std::time::{Duration, SystemTime};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::rustls::{self, OwnedTrustAnchor};
use tokio_rustls::TlsConnector;
use url::Url;

#[derive(Debug, Clone)]
struct CheckData {
    body: Vec<u8>,
    headers: String,
}

pub struct WebTitlePlugin {
    name: String,
    ports: Vec<u16>,
    types: Vec<String>,
    user_agent: String,
    timeout: u64,
    rule_datas: Vec<RuleData>,
    md5_datas: Vec<Md5Data>,
}

#[async_trait]
impl ScanPlugin for WebTitlePlugin {
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
            None => self.ports.contains(port),
            Some(info) => true,
        }
    }
    async fn scan(&self, info: &mut HostInfo) -> Result<Vec<ScanResult>> {
        debug!(
            "开始获取Web标题，初始信息: host={}, port={}",
            info.host, info.port
        );

        let (check_data, url) = match self.go_web_title(info).await {
            Ok((check_data, url)) => (check_data, url),
            Err(e) => {
                error!("网站标题 {} 错误: {}", info.url, e);
                return Err(e);
            }
        };

        // 进行指纹识别
        let infostr = self.info_check(&url, &check_data);
        debug!("信息检查完成，获得信息: {:?}", infostr);
        info.infostr = infostr.clone();
        // 检查是否为打印机
        for info_item in &infostr {
            if info_item == "打印机" {
                debug!("检测到打印机，停止扫描");
                return Ok(vec![]);
            }
        }

        Ok(vec![])
    }
}

impl WebTitlePlugin {
    // 创建新实例
    pub fn new() -> Self {
        Self {
            name: "web_title".to_string(),
            ports: vec![80, 443, 8080, 8000, 8888, 8081, 8082, 21332],
            types: vec!["web".to_string()],
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36".to_string(),
            timeout: 10, // 默认10秒超时
            rule_datas: Vec::new(),
            md5_datas: Vec::new(),
        }
    }

    pub fn with_config(mut self, config: &Config) -> Self {
        let timeout = config.get_timeout();
        self.timeout = timeout;
        self.rule_datas = config.rule_datas.clone();
        self.md5_datas = config.md5_datas.clone();
        self
    }

    // 指纹识别
    fn info_check(&self, url: &str, check_data: &[CheckData]) -> Vec<String> {
        let mut matched_infos = Vec::new();

        // 遍历检查数据
        for data in check_data {
            // 规则匹配检查
            for rule in &self.rule_datas {
                let pattern = &rule.rule;
                let re = match Regex::new(pattern) {
                    Ok(re) => re,
                    Err(e) => {
                        error!("规则匹配错误 [{}]: {}", rule.name, e);
                        continue;
                    }
                };

                let content = match rule.rule_type.as_str() {
                    "code" => match str::from_utf8(&data.body) {
                        Ok(s) => s,
                        Err(_) => continue,
                    },
                    _ => &data.headers,
                };

                if re.is_match(content) {
                    matched_infos.push(rule.name.clone());
                }
            }

            if let Some(name) = self.calc_md5(&data.body) {
                matched_infos.push(name);
            }
        }

        // 去重处理
        matched_infos.sort();
        matched_infos.dedup();

        // 输出结果
        if !matched_infos.is_empty() {
            let result = format!("发现指纹 目标: {:<25} 指纹: {:?}", url, matched_infos);
            info!("{}", result);
            return matched_infos;
        }

        vec![]
    }

    fn calc_md5(&self, body: &[u8]) -> Option<String> {
        let content_md5 = format!("{:x}", md5::compute(body));

        // 比对MD5指纹库
        for md5_info in &self.md5_datas {
            if content_md5 == md5_info.md5_str {
                return Some(md5_info.name.clone());
            }
        }

        None
    }

    async fn go_web_title(&self, info: &HostInfo) -> Result<(Vec<CheckData>, String)> {
        let mut url = info.url.clone();
        debug!("开始处理URL: {}", url);

        if url.is_empty() {
            debug!("URL为空，根据端口生成URL");
            match info.port.to_string().as_str() {
                "80" => {
                    url = format!("http://{}", info.host);
                }
                "443" => {
                    url = format!("https://{}", info.host);
                }
                _ => {
                    let host = format!("{}:{}", info.host, info.port);
                    debug!("正在检测主机协议: {}", host);
                    let protocol = self.get_protocol(&host).await?;
                    debug!("检测到协议: {}", protocol);
                    url = format!("{}://{}:{}", protocol, info.host, info.port);
                }
            }
        } else {
            if !url.contains("://") {
                debug!("URL未包含协议，开始检测");
                let host = url.split('/').next().unwrap_or(&url);
                let protocol = self.get_protocol(host).await?;
                debug!("检测到协议: {}", protocol);
                url = format!("{}://{}", protocol, url);
            }
        }
        debug!("协议检测完成后的URL: {}", url);

        debug!("第一次尝试访问URL");
        let (err, result, mut check_data) = self.get_url(&url, 1).await;
        debug!("第一次访问结果 - 错误: {:?}, 返回信息: {}", err, result);

        if let Err(e) = err {
            if !e.to_string().contains("EOF") {
                return Err(e);
            }
        }

        let mut final_url = url.clone();
        if result.contains("://") {
            debug!("检测到重定向到: {}", result);
            final_url = result.clone();
            let (err, _, new_check_data) = self.get_url(&final_url, 3).await;
            if let Err(e) = err {
                return Err(e);
            }
            check_data.extend(new_check_data);
        }

        if result == "https" && !final_url.starts_with("https://") {
            debug!("正在升级到HTTPS");
            final_url = final_url.replace("http://", "https://");
            debug!("升级后的URL: {}", final_url);
            let (_err, result, new_check_data) = self.get_url(&final_url, 1).await;
            check_data.extend(new_check_data);

            // 处理升级后的跳转
            if result.contains("://") {
                debug!("HTTPS升级后发现重定向到: {}", result);
                final_url = result;
                let (err, _, new_check_data) = self.get_url(&final_url, 3).await;
                if let Err(e) = err {
                    return Err(e);
                }
                check_data.extend(new_check_data);
            }
        }

        Ok((check_data, final_url))
    }

    async fn get_url(&self, url: &str, flag: u8) -> (Result<()>, String, Vec<CheckData>) {
        debug!("get_url开始执行 - URL: {}, 标志位: {}", url, flag);
        let mut check_data = Vec::new();

        let mut target_url = url.to_string();
        if flag == 2 {
            debug!("处理favicon.ico URL");
            match Url::parse(url) {
                Ok(parsed_url) => {
                    target_url = format!(
                        "{}://{}/favicon.ico",
                        parsed_url.scheme(),
                        parsed_url.host_str().unwrap_or("")
                    );
                }
                Err(_) => {
                    target_url = format!("{}/favicon.ico", url);
                }
            }
            debug!("favicon URL: {}", target_url);
        }

        let client_builder = ClientBuilder::new()
            .timeout(Duration::from_secs(self.timeout))
            .danger_accept_invalid_certs(true)
            .user_agent(&self.user_agent);

        // 根据flag来设置重定向策略
        let client = match if flag == 1 {
            client_builder.redirect(Policy::none()).build()
        } else {
            client_builder.build()
        } {
            Ok(client) => client,
            Err(e) => {
                return (
                    Err(anyhow!("创建HTTP客户端失败: {}", e)),
                    String::new(),
                    check_data,
                );
            }
        };
        debug!("开始发送HTTP请求");
        let resp = match client.get(&target_url).send().await {
            Ok(resp) => resp,
            Err(e) => {
                debug!("HTTP请求失败: {}", e);
                if url.starts_with("http://") {
                    return (Ok(()), "https".to_string(), check_data);
                }
                return (
                    Err(anyhow!("HTTP请求失败: {}", e)),
                    String::new(),
                    check_data,
                );
            }
        };

        let headers_str = format!("{:?}", resp.headers());

        let status_code = resp.status().as_u16();
        let content_length = resp
            .headers()
            .get("content-length")
            .map(|v| v.to_str().unwrap_or("0").to_string())
            .unwrap_or_else(|| "0".to_string());
        let location = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_string());
        let headers_clone = resp.headers().clone();

        let body = match resp.bytes().await {
            Ok(bytes) => bytes.to_vec(),
            Err(e) => {
                debug!("读取响应内容失败: {}", e);
                return (
                    Err(anyhow!("读取响应内容失败: {}", e)),
                    String::new(),
                    check_data,
                );
            }
        };
        debug!("成功读取响应内容，长度: {}", body.len());

        check_data.push(CheckData {
            body: body.clone(),
            headers: headers_str.clone(),
        });
        debug!("已保存检查数据");

        // 处理非favicon请求
        let mut reurl = String::new();
        if flag != 2 {
            // 获取页面标题
            let title = self.get_title(&body);
            let mut length = content_length.clone();
            if length == "0" {
                // 如果之前没获取到content-length，使用body长度
                length = body.len().to_string();
            }

            // 收集服务器信息
            let mut server_info = HashMap::new();
            server_info.insert("title".to_string(), title.clone());
            server_info.insert("length".to_string(), length.clone());
            server_info.insert("status_code".to_string(), status_code.to_string());

            for (k, v) in headers_clone.iter() {
                if let Ok(v_str) = v.to_str() {
                    server_info.insert(k.to_string().to_lowercase(), v_str.to_string());
                }
            }

            // 检查重定向
            if let Some(loc) = location {
                reurl = loc;
                server_info.insert("redirect_url".to_string(), reurl.clone());
            }

            // 从URL中提取端口
            let port_num = match url.parse::<Url>() {
                Ok(parsed_url) => parsed_url
                    .port()
                    .unwrap_or_else(|| match parsed_url.scheme() {
                        "http" => 80,
                        "https" => 443,
                        _ => 0,
                    }) as u64,
                Err(_) => 0,
            };

            let mut details = HashMap::new();
            details.insert(
                "port".to_string(),
                serde_json::Value::Number(serde_json::Number::from(port_num)),
            );
            details.insert(
                "service".to_string(),
                serde_json::Value::String("http".to_string()),
            );
            details.insert(
                "title".to_string(),
                serde_json::Value::String(title.clone()),
            );
            details.insert(
                "url".to_string(),
                serde_json::Value::String(target_url.clone()),
            );
            details.insert(
                "status_code".to_string(),
                serde_json::Value::Number(serde_json::Number::from(status_code)),
            );
            details.insert(
                "length".to_string(),
                serde_json::Value::String(length.clone()),
            );

            let result = ScanResult {
                time: SystemTime::now(),
                r#type: "SERVICE".to_string(),
                target: target_url.clone(),
                status: "identified".to_string(),
                details,
            };

            let mut log_msg = format!(
                "网站标题 {:<25} 状态码:{:<3} 长度:{:<6} 标题:{}",
                target_url, status_code, length, title
            );
            if !reurl.is_empty() {
                log_msg.push_str(&format!(" 重定向地址: {}", reurl));
            }
            info!("{}", log_msg);
        }

        if !reurl.is_empty() {
            debug!("返回重定向URL: {}", reurl);
            return (Ok(()), reurl, check_data);
        }
        if status_code == 400 && !url.starts_with("https") {
            debug!("返回HTTPS升级标志");
            return (Ok(()), "https".to_string(), check_data);
        }
        debug!("get_url执行完成，无特殊返回");
        (Ok(()), String::new(), check_data)
    }

    fn get_title(&self, body: &[u8]) -> String {
        debug!("开始提取网页标题");

        let body_str = match String::from_utf8(body.to_vec()) {
            Ok(s) => s,
            Err(_) => String::from_utf8_lossy(body).to_string(),
        };

        let re = Regex::new(r"(?ims)<title.*?>(.*?)</title>").unwrap();
        let mut title = "无标题".to_string();

        if let Some(captures) = re.captures(&body_str) {
            if let Some(matched) = captures.get(1) {
                title = matched.as_str().to_string();
                debug!("找到原始标题: {}", title);

                title = title.trim().to_string();
                title = title.replace("\n", "");
                title = title.replace("\r", "");
                title = title.replace("&nbsp;", " ");

                // 处理过长的标题
                if title.len() > 100 {
                    debug!("标题超过100字符，进行截断");
                    title = title[..100].to_string();
                }

                if title.is_empty() {
                    debug!("标题为空，使用双引号代替");
                    title = "\"\"".to_string();
                }
            }
        } else {
            debug!("未找到标题标签");
        }

        debug!("最终标题: {}", title);
        title
    }

    // 检测目标主机的协议类型(HTTP/HTTPS)
    async fn get_protocol(&self, host: &str) -> Result<String> {
        debug!(
            "开始检测主机协议 - 主机: {}, 超时: {}秒",
            host, self.timeout
        );
        if host.ends_with(":80") || !host.contains(':') {
            debug!("检测到HTTP标准端口或无端口，使用HTTP协议");
            return Ok("http".to_string());
        } else if host.ends_with(":443") {
            debug!("检测到HTTPS标准端口，使用HTTPS协议");
            return Ok("https".to_string());
        }

        debug!("尝试建立TCP连接");
        let socket_addr = match host.to_socket_addrs() {
            Ok(mut addrs) => {
                if let Some(addr) = addrs.next() {
                    addr
                } else {
                    return Err(anyhow!("无法解析主机地址: {}", host));
                }
            }
            Err(e) => {
                return Err(anyhow!("解析主机地址失败: {}", e));
            }
        };

        // 设置连接超时
        let tcp_connect = TcpStream::connect(socket_addr);
        let tcp_timeout = Duration::from_secs(self.timeout);

        let tcp_stream = match timeout(tcp_timeout, tcp_connect).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                return Err(anyhow!("TCP连接失败: {}", e));
            }
            Err(_) => {
                return Err(anyhow!("TCP连接超时"));
            }
        };

        // 设置TLS连接器
        let mut root_cert_store = rustls::RootCertStore::empty();
        #[allow(deprecated)]
        root_cert_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject.as_ref().to_vec(),
                ta.subject_public_key_info.as_ref().to_vec(),
                <Option<rustls_pki_types::Der<'_>> as Clone>::clone(
                    &ta.name_constraints,
                )
                .map(|nc| nc.as_ref().to_vec()),
            )
        }));

        let config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(config));

        // 提取服务器名称
        let server_name = match host.split(':').next() {
            Some(name) => name,
            None => return Err(anyhow!("无法提取主机名")),
        };
        
        debug!("开始TLS握手");
        let domain = match rustls::ServerName::try_from(server_name) {
            Ok(domain) => domain,
            Err(e) => {
                debug!("无效的服务器名称: {}", e);
                return Ok("http".to_string());
            }
        };

        match timeout(tcp_timeout, connector.connect(domain, tcp_stream)).await {
            Ok(Ok(_)) => {
                debug!("TLS握手成功，使用HTTPS协议");
                Ok("https".to_string())
            }
            Ok(Err(e)) => {
                if e.to_string().contains("handshake failure") {
                    debug!("TLS握手失败但确认是HTTPS协议");
                    Ok("https".to_string())
                } else {
                    debug!("TLS握手失败: {}，使用HTTP协议", e);
                    Ok("http".to_string())
                }
            }
            Err(_) => {
                debug!("TLS握手超时，使用HTTP协议");
                Ok("http".to_string())
            }
        }
    }
}
