# EvilTwin-ESP8266

[中文](#中文) | [English](#english)

---

## 中文

基于 ESP8266 的 Wi-Fi 钓鱼攻击设备 —— 克隆目标 Wi-Fi，踢下线，捕获密码。

### 功能

| 模式 | 说明 |
|------|------|
| **配置模式** | 创建 `EvilTwin-Setup` 热点，扫描周边 Wi-Fi，网页选择目标 |
| **攻击模式** | 克隆目标 SSID，发送 deauth 踢人，Captive Portal 钓鱼捕获密码 |

### 硬件

- NodeMCU / Wemos D1 mini / 任意 ESP8266 开发板
- Micro-USB 数据线

### 烧录

1. 安装 [Arduino IDE](https://www.arduino.cc/en/software)
2. 添加 ESP8266 开发板支持：`文件 → 首选项 → 附加开发板管理器网址` 填入
   ```
   https://arduino.esp8266.com/stable/package_esp8266com_index.json
   ```
3. `工具 → 开发板 → 开发板管理器` 搜索 `esp8266` 安装
4. 打开 `esp8266_evil_twin.ino`，选择开发板 `NodeMCU 1.0`（或对应型号）
5. 点击上传

### 使用

1. **上电**：如果没配过目标，自动进入配置模式
2. **手机连** `EvilTwin-Setup` 热点，浏览器打开 `http://192.168.4.1`
3. **选择目标 Wi-Fi** 点击 → 设备自动保存并重启
4. **攻击开始**：热点名变为目标 SSID，持续发送 deauth 踢掉原客户端
5. **受害者重连** 到你的热点 → 弹出 "WiFi 认证" 页面 → 输入密码 → 串口输出密码
6. **恢复出厂**：按住 GPIO0（Flash 按钮）上电，保持 3 秒清除配置

### 技术细节

| 组件 | 实现 |
|------|------|
| Deauth | `wifi_send_pkt_freedom()` 发送 802.11 去认证帧，每 200ms 爆发 8 包 |
| DNS 劫持 | `DNSServer` 拦截所有 DNS 请求重定向到 `192.168.4.1` |
| Captive Portal | `ESP8266WebServer` 302 重定向 + 钓鱼页面 |
| 持久化 | `EEPROM` 存储目标 BSSID / SSID / 信道，断电保留 |

### ⚠️ 免责声明

**仅限在自己的网络或已获授权的测试环境中使用。**
未经授权攻击他人 Wi-Fi 网络属于违法行为。

---

## English

ESP8266-based Wi-Fi phishing device — clone a target network, kick clients off, and capture the password.

### Features

| Mode | Description |
|------|-------------|
| **Config Mode** | Creates `EvilTwin-Setup` AP, scans nearby Wi-Fi, web UI to pick a target |
| **Attack Mode** | Clones target SSID, sends deauth bursts, captive portal captures password |

### Hardware

- NodeMCU / Wemos D1 mini / any ESP8266 dev board
- Micro-USB cable

### Flashing

1. Install [Arduino IDE](https://www.arduino.cc/en/software)
2. Add ESP8266 board support: `File → Preferences → Additional Boards Manager URLs`
   ```
   https://arduino.esp8266.com/stable/package_esp8266com_index.json
   ```
3. `Tools → Board → Boards Manager` search `esp8266` and install
4. Open `esp8266_evil_twin.ino`, select board `NodeMCU 1.0` (or your model)
5. Upload

### Usage

1. **Power on** — enters config mode automatically if no target saved
2. **Phone** connects to `EvilTwin-Setup`, open `http://192.168.4.1`
3. **Pick a target Wi-Fi** → device saves config and reboots
4. **Attack starts** — AP renamed to target SSID, deauth floods original clients
5. **Victim reconnects** to your AP → captive portal asks for password → serial prints it
6. **Factory reset** — hold GPIO0 (Flash button) at boot for 3 seconds

### Tech Details

| Component | Implementation |
|-----------|---------------|
| Deauth | `wifi_send_pkt_freedom()` sends 802.11 deauth frames, 8-packet burst every 200ms |
| DNS Hijack | `DNSServer` redirects all queries to `192.168.4.1` |
| Captive Portal | `ESP8266WebServer` 302 redirect + phishing page |
| Storage | `EEPROM` persists target BSSID / SSID / channel across reboots |

### ⚠️ Disclaimer

**For use only on your own network or authorized test environments.**
Unauthorized attacks on others' Wi-Fi networks are illegal.
