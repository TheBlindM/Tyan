use clap::{Parser, ValueEnum,ArgAction};
use serde::Deserialize;

/// 表示端口扫描运行的策略。
///   - Serial 将从开始到结束运行，例如 1 到 1_000。
///   - Random 将随机化端口扫描的顺序。
#[derive(Deserialize, Debug, ValueEnum, Clone, Copy, PartialEq, Eq)]
pub enum ScanOrder {
    Serial,
    Random,
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}


#[derive(Parser)]
#[command(name = "tyan", version = "0.1", about = "一款功能强大的内网安全扫描工具", disable_help_flag(true))]
pub struct Cli {
    /// 目标主机 (例如: 192.168.1.1, 192.168.1.1/24, 192.168.1.1-192.168.1.100)
    #[arg(short = 'h', long = "host",value_delimiter = ',')]
    pub hosts: Option<Vec<String>>,

    /// 从文件读取目标主机列表
    #[arg(long = "host-file", visible_aliases = ["hf"])]
    pub host_file: Option<String>,

    /// 目标端口 (例如: 80,443,8000-8100) 默认为21,22,80,443,3306,6379,8080
    #[arg(short, long)]
    pub port: Option<String>,

    /// 从文件读取目标端口列表
    #[arg(long = "port-file", visible_aliases = ["pf"])]
    pub port_file: Option<String>,

    /// 排除端口 (例如: 22,3306)
    #[arg(long = "exclude-ports",value_delimiter = ',')]
    pub exclude_ports: Option<Vec<u16>>,

    /// 要执行的扫描顺序。"serial" 选项将按升序扫描端口，
    /// 而 "random" 选项将随机扫描端口。
    #[arg(long, value_enum, ignore_case = true, default_value = "serial")]
    pub port_scan_order: ScanOrder,

    /// 批处理大小
    #[arg(short, long, default_value = "1500")]
    pub batch_size: usize,

    /// 超时时间(秒)
    #[arg(long, default_value = "3")]
    pub timeout: String,

    /// 使用系统ping代替ICMP
    #[arg(long, action = ArgAction::SetTrue)]
    pub ping: bool,

    /// 跳过存活检测
    #[arg(long, action = ArgAction::SetTrue)]
    pub no_ping: bool,

    /// 服务指纹识别
    #[arg(short, long, action = ArgAction::SetTrue)]
    pub fingerprint: bool,


    ///最大重试次数
    #[arg(long, default_value = "3")]
    pub retries: u8,

    /// 指定扫描模式 (例如：ModeService)
    #[arg(short = 'm', long = "mode")]
    pub mode: Option<String>,

    /// 日志级别 (debug, info, warn, error)
    #[arg(short = 'l', long = "log-level", default_value = "info")]
    pub log_level: String,

    /// 禁用暴力破解
    #[arg(long = "disable-brute", action = ArgAction::SetTrue)]
    pub disable_brute: bool,

    ///密码文件路径
    #[arg(long = "password-file",visible_aliases = ["pwdf"])]
    pub password_file: Option<String>,

    ///用户名文件路径
    #[arg(long = "username-file",visible_aliases = ["userf"])]
    pub username_file: Option<String>,

    ///附加用户名
    #[arg(long = "additional-usernames",visible_aliases = ["usera"])]
    pub additional_usernames: Option<String>,

    ///附加密码
    #[arg(long = "additional-passwords",visible_aliases = ["pwda"])]
    pub additional_passwords: Option<String>,

    /// 将结果导出到文件，输出格式 (json, md)，根据输出文件后缀自动判断
    #[arg(short = 'o', long = "output")]
    pub output_file: Option<String>,

    /// 显示帮助信息
    #[arg(long = "help", action = ArgAction::Help)]
    pub help: Option<bool>,
}
