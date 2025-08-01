# Burp Suite RCE Detection Extension

🔍 **一个专业的Burp Suite扩展，用于自动检测远程代码执行(RCE)漏洞**

![Language](https://img.shields.io/badge/Language-Kotlin-orange)
![Burp API](https://img.shields.io/badge/Burp%20API-Montoya%202025.7-red)
![License](https://img.shields.io/badge/License-MIT-green)

## 📋 目录

- [功能特性](#-功能特性)
- [技术栈](#-技术栈)
- [安装方式](#-安装方式)
- [使用方法](#-使用方法)
- [检测原理](#-检测原理)
- [配置说明](#-配置说明)
- [开发指南](#-开发指南)

## 🚀 功能特性

### 🎯 全面的RCE检测
- **多种检测方式**：支持回显型、带外(OOB)、时间盲注三种检测方法
- **智能负载均衡**：内置50线程协程池，高效并发处理
- **多种参数类型**：支持URL参数、表单数据、JSON数据的自动化测试

### 🔧 高级功能
- **异步处理**：基于Kotlin协程的非阻塞式扫描
- **智能过滤**：自动过滤静态资源，减少误报
- **实时日志**：详细的扫描过程记录
- **自动上报**：发现漏洞自动发送到Burp Organizer

### 📊 支持的攻击载荷
- **Echo-based载荷**：通过响应回显检测命令执行
- **OOB载荷**：使用Burp Collaborator进行带外检测
- **Time-based载荷**：通过延时响应检测盲注漏洞

## 🛠 技术栈

- **语言**: Kotlin 1.9+
- **构建工具**: Maven 3.6+
- **API**: Burp Suite Montoya API 2025.7
- **异步框架**: Kotlinx Coroutines 1.9.0
- **JSON处理**: Jackson 2.15.2
- **测试框架**: JUnit 5.10.0

## 📦 安装方式

### 方法一：使用预编译的JAR文件

1. 从[Releases页面](https://github.com/Rain1er/detect/releases)下载最新的`detect-1.0.jar`文件
2. 打开Burp Suite
3. 进入 `Extensions` → `Installed` → `Add`
4. 选择`Java`类型，加载下载的JAR文件

### 方法二：从源码编译

```bash
# 克隆项目
git clone https://github.com/Rain1er/detect.git
cd detect

# 编译项目
mvn clean package

# 生成的JAR文件位于 target/detect-1.0.jar
```

## 🎮 使用方法

### 1. 加载扩展
安装扩展后，在Burp Suite的`Output`选项卡中会看到：
```
Loading vulnerability Detector
```

### 2. 开始扫描
扩展会自动拦截HTTP请求并进行以下检测：

- **GET请求**：自动测试URL参数
- **POST请求**：根据Content-Type自动选择测试方式
  - `application/x-www-form-urlencoded`：表单参数测试
  - `application/json`：JSON字段递归测试
  - `multipart/form-data`：多部分表单测试（开发中）

### 3. 查看结果
- **实时日志**：在`Output`选项卡查看扫描过程
- **漏洞报告**：发现的漏洞会自动发送到`Organizer`
- **响应分析**：检查响应内容中的命令执行证据

## 🔬 检测原理

### Echo-based检测
```kotlin
// 示例载荷
"`id`", ";id;", "';id;'", "\";id;\""
```
通过在参数中注入命令，检查响应是否包含`uid=`等命令执行结果。

### OOB检测
```kotlin
// 示例载荷
"`curl\${IFS}{{interactsh-url}}`"
```
使用Burp Collaborator生成唯一URL，检测服务器是否向该URL发起请求。

### Time-based检测
```kotlin
// 示例载荷 - 2秒延时
"`sleep\${IFS}2`", ";sleep\${IFS}2;"

// 示例载荷 - 3秒延时  
"`sleep\${IFS}3`", ";sleep\${IFS}3;"
```
通过双重确认机制减少误报：先发送2秒延时载荷，如果响应时间异常，再发送3秒延时载荷进行确认。

## ⚙️ 配置说明

### 线程池配置
```kotlin
// 默认50线程并发
private val fuzzingDispatcher = Executors.newFixedThreadPool(50).asCoroutineDispatcher()
```

### 静态资源过滤
扩展会自动跳过以下文件类型的扫描：
```
js, css, png, jpg, gif, ico, pdf, zip, rar, 7z, mp3, mp4, avi, 等...
```

### 载荷定制
在`src/main/kotlin/rce/Payload.kt`中可以自定义攻击载荷：

```kotlin
class Payload {
    val EchoInject = listOf(
        "`id`",
        ";id;",
        // 添加自定义载荷
    )
    
    val OOBInject = listOf(
        "`curl\${IFS}{{interactsh-url}}`",
        // 添加自定义OOB载荷
    )
}
```

## 🔧 开发指南

### 项目结构
```
src/
├── main/kotlin/
│   ├── rain/
│   │   ├── Init.kt                           # 扩展入口点
│   │   ├── DetectorHttpRequestHandler.kt     # 请求处理器
│   │   ├── DetectorHttpResponseHandler.kt    # 响应处理器
│   │   └── rce/
│   │       ├── Utils.kt                      # 核心检测逻辑
│   │       └── Payload.kt                    # 攻击载荷定义
│   └── resources/
└── test/kotlin/
    └── rain/
        └── UtilsTest.kt                      # 单元测试
```

### 添加新的检测类型

1. 在`Payload.kt`中定义新载荷：
```kotlin
val CustomInject = listOf(
    "your-custom-payload-1",
    "your-custom-payload-2"
)
```

2. 在`Utils.kt`中添加检测逻辑：
```kotlin
suspend fun customFuzzing(request: InterceptedRequest, api: MontoyaApi) {
    // 实现自定义检测逻辑
}
```

3. 在`DetectorHttpRequestHandler.kt`中调用：
```kotlin
GlobalScope.launch {
    Utils.customFuzzing(interceptedRequest, api)
}
```

### 本地开发环境

1. **环境要求**：
   - JDK 17+
   - Maven 3.6+
   - Burp Suite Professional

2. **开发步骤**：
```bash
# 克隆项目
git clone https://github.com/Rain1er/detect.git
cd detect

# 运行测试
mvn test

# 编译打包
mvn clean package

# 在Burp中加载 target/detect-1.0.jar
```


### 报告Bug
请在[Issues页面](https://github.com/Rain1er/detect/issues)提交Bug报告，包含：
- 详细的错误描述
- 复现步骤
- 环境信息（Burp版本、操作系统等）

### 提交功能请求
在Issues中提交功能请求，说明：
- 功能的详细描述
- 使用场景
- 期望的实现方式

### 代码贡献
1. Fork项目
2. 创建功能分支：`git checkout -b feature/new-feature`
3. 提交更改：`git commit -am 'Add new feature'`
4. 推送分支：`git push origin feature/new-feature`
5. 提交Pull Request

## ⚠️ 免责声明

此工具仅用于授权的安全测试和教育目的。使用者应确保：

1. 仅在获得明确授权的系统上使用
2. 遵守当地法律法规
3. 不用于任何恶意目的
4. 承担使用此工具的全部责任

📧 **联系方式**: [issues](https://github.com/Rain1er/detect/issues)
