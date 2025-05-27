# Tyan (天眼)

Tyan 一款内网安全扫描工具，使用 Rust 编写，具有高性能和并发处理能力。支持主机存活、端口扫描、指纹识别、漏洞扫描的综合工具集。
**该项目目前处于早期阶段，目标fscan**
## 主要特性

- **主机发现**：支持 ICMP 和系统 ping 进行主机存活探测
- **端口扫描**：高速并发 TCP 端口扫描
- **服务指纹识别**：识别开放端口上运行的服务类型和版本
- **SSH 服务测试**：支持并发密码暴力破解，提高效率
- **Web 应用扫描**：根据 poc验证web 应用程序漏洞，获取网站标题
- **RabbitMQ 测试**：专用插件用于 RabbitMQ 服务测试
- **跨平台**：支持 Windows、macOS 和 Linux
- **高并发**：基于 Tokio 异步运行时，提供优秀的性能和并行处理能力
- **可扩展**：模块化的插件架构，易于添加新功能
- **结果导出**：支持 JSON 和 Markdown 格式导出扫描结果

## 安装

### 二进制发布版本

从 [Releases](https://github.com/TheBlindM/Tyan/releases) 页面下载最新的预编译二进制文件：

- Windows: `tyan-windows.exe`
- macOS: `tyan-macos`
- Linux: `tyan-linux`

### 从源码构建

```bash
# 克隆仓库
git clone https://github.com/TheBlindM/Tyan.git
cd Tyan

# 构建发布版本
cargo build --release

# 二进制文件将位于 target/release/Tyan
```

## 使用方法
```bash
  ______                
 /_  __/_  ______ _____ 
  / / / / / / __ `/ __ \
 / / / /_/ / /_/ / / / /
/_/  \__, /\__,_/_/ /_/ 
    /____/              
    
版本 v0.1.1
一款功能强大的内网安全扫描工具

Usage: Tyan [OPTIONS] --host <HOSTS>

Options:
  -h, --host <HOSTS>                   目标主机 (例如: 192.168.1.1, 192.168.1.1/24, 192.168.1.1-192.168.1.100)
  -p, --port <PORT>                    目标端口 (例如: 80,443,8000-8100) [default: 21,22,80,443,3306,6379,8080]
      --exclude-ports <EXCLUDE_PORTS>  排除端口 (例如: 22,3306)
  -t, --threads <THREADS>              线程数 [default: 60]
      --timeout <TIMEOUT>              超时时间(秒) [default: 3]
      --ping                           使用系统ping代替ICMP
      --no-ping                        跳过存活检测
  -f, --fingerprint                    服务指纹识别
      --retries <RETRIES>              最大重试次数 [default: 3]
  -m, --mode <MODE>                    指定扫描模式 (例如：ModeService)
  -l, --log-level <LOG_LEVEL>          日志级别 (debug, info, warn, error) [default: info]
      --disable-brute                  禁用暴力破解
      --password-file <PASSWORD_FILE>  密码文件路径               [aliases: --pwdf]
      --username-file <USERNAME_FILE>  用户名文件路径             [aliases: --userf]
      --additional-usernames <ADDITIONAL_USERNAMES>  附加用户名  [aliases: --usera]
      --additional-passwords <ADDITIONAL_PASSWORDS>  附加密码    [aliases: --pwda]   
  -o, --output <OUTPUT_FILE>           将结果导出到文件，输出格式 (json, md)，根据输出文件后缀自动判断
      --help                           显示帮助信息
  -V, --version                        Print version
```

```bash
# 基础用法
./Tyan -h <目标> -p <端口范围> [选项]

# 显示帮助信息
./Tyan --help

# 扫描单个主机的特定端口
./Tyan -h 192.168.1.1 -p 22,80,443

# 扫描整个子网
./Tyan -h 192.168.1.0/24 -p 80-1000

# 启用服务指纹识别
./Tyan -h 192.168.1.1 -p 22,80,443 -f

# 导出扫描结果
./Tyan -h 192.168.1.1 -p 1-1000 -o results.json
```

### SSH 模块

SSH 模块支持并发密码暴力破解，相比顺序执行大幅提高效率：

```bash
# 使用默认的并发数（20）进行 SSH 密码破解
./Tyan -h 192.168.1.1 -p 22 
```

### 高级选项

```bash
# 跳过主机存活检测
./Tyan -h 192.168.1.0/24 -p 80,443 --no-ping

# 使用系统 ping 替代 ICMP
./Tyan -h 192.168.1.0/24 -p 80,443 --ping

# 设置超时和线程数
./Tyan -h 192.168.1.0/24 -p 80,443 -t 100 --timeout 5

# 禁用暴力破解模块
./Tyan -h 192.168.1.0/24 -p 80,443 --disable-brute
```


## 开发

### 环境要求

- Rust 1.80.0 或更高版本

### 设置开发环境

```bash
# 安装依赖
cargo build

```

## 贡献

欢迎提交 Pull Request 来改进 Tyan！

## 许可证

本项目采用 [MIT 许可证](LICENSE) 进行许可。

## 致谢

- fscan项目
- 影舞者的指导

----

<p style="text-align: center;">
  <img src="doc/gzh.jpg" alt="gzh" style="display: inline-block; width: 40%; margin: 1%;">
  <img src="doc/wx.jpg" alt="wx" style="display: inline-block; width: 40%; height: 380px; margin: 1%;">
</p>
