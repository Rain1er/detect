# RCE Detection Extension

## 简介
`RCE Detection Extension` 是一个基于 montoya-api 开发的Burp Suite 的插件，旨在帮助安全研究人员和开发者快速发现远程代码执行(RCE)漏洞。

参考项目：

https://github.com/PortSwigger/burp-extensions-montoya-api

## 功能特性
- **主动扫描**：支持通过上下文菜单发送请求进行主动扫描。
- **被动扫描**：支持拦截代理请求并自动检测潜在的RCE漏洞。
- **多种检测方式**：支持回显型、带外(OOB)、时间盲注三种检测方法。
- **多线程支持**：内置50线程协程池，高效并发处理。
- **智能过滤**：自动过滤静态资源，减少误报。
- **多种参数类型**：支持URL参数、表单数据、JSON数据的自动化测试。

## 安装
1. 克隆项目到本地：
   ```bash
   git clone https://github.com/Rain1er/detect
   cd detect
   ```
2. 使用 Maven 构建项目：
   ```bash
   mvn clean package
   ```
3. 在 Burp Suite 中加载生成的插件 JAR 文件：
    - 进入 Burp Suite 的 `Extensions` 标签页。
    - 点击 `Add` 按钮，选择生成的 `detect-1.0.jar` 文件。

## 使用方法
1. **主动扫描**：
    - 右键点击 HTTP 请求，选择 `Send to RCE Detector`。
    - 插件将自动生成 payload 并发送请求，结果会显示在插件的界面中。

2. **被动扫描**：
    - 启用扩展后会自动拦截代理请求。
    - 插件会自动检测潜在的RCE漏洞并发送到Burp Organizer。

3. **检测类型**：
    - **Echo-based检测**：通过响应回显检测命令执行
    - **OOB检测**：使用Burp Collaborator进行带外检测
    - **Time-based检测**：通过延时响应检测盲注漏洞

## 载荷示例
以下是扩展使用的部分检测载荷：
```bash
# Echo-based载荷
"`id`"
";id;"
"';id;'"

# Time-based载荷  
"sleep 5"
"ping -c 5 127.0.0.1"

# OOB载荷
"nslookup {collaborator-domain}"
"curl {collaborator-domain}"
```

## 开发者信息
- **作者**: raindrop
- **版本**: 1.0
- **许可证**: MIT

欢迎提交问题和贡献代码！如需帮助，请联系 [rain.xinc@gmail.com]。
