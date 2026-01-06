# 🐬 SMART DOLPHIN HUNTER v2.0 AGGRO

**A security awareness & penetration testing companion with emotional AI**

![Smart Dolphin Hunter](https://img.shields.io/badge/Platform-ESP32-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Version](https://img.shields.io/badge/Version-2.0_AGGRO-red)

## 📖 Overview

Smart Dolphin Hunter is an **ESP32-based educational security tool** that combines a virtual pet simulation with real network security testing capabilities. The "dolphin" evolves based on your network exploration activities, learning from vulnerabilities found in your environment.

> ⚠️ **IMPORTANT**: This tool is for **EDUCATIONAL PURPOSES ONLY**. Use only on your own devices/networks or with explicit permission.

## 🎮 Features

### 🐬 Virtual Pet System
- **8 Evolution Stages**: Egg → Hatch → Baby → Young → Teen → Adult → Elder → Cyber
- **Emotional AI**: Mood system (-100 to 100) with aggression levels
- **Dynamic Behavior**: Happy, hungry, angry states affect gameplay
- **Visual Animations**: OLED display with animated dolphin sprites

### 🔍 Security Scanning Capabilities
- **WiFi Network Scanning**: Detect open networks and connect automatically
- **Port Vulnerability Scanner**: Checks 30+ common vulnerable ports
- **BLE Device Discovery**: Scan for Bluetooth Low Energy devices
- **Vulnerability Database**: 17 BLE vulnerabilities + 46 network port vulnerabilities

### ⚔️ "Mood-Based" Attack Simulation
When the dolphin gets angry (low mood + high aggression), it can perform:
- **Limited Deauth Attacks**: WiFi deauthentication (broadcast only)
- **Beacon Spam**: Creates fake WiFi access points
- **BLE Spam**: Advertises fake Bluetooth devices
- **Port Flood**: Tests common ports on gateway
- **Safety Features**: Confirmation prompts, private network checks, cooldowns

### 📊 Statistics & Tracking
- **Comprehensive Stats**: Network data, vulnerabilities found, XP earned
- **Tabbed Interface**: General, Network, Security, Status views
- **History Log**: Keeps track of all scans and attacks
- **Persistent Storage**: Saves progress via Preferences

## 🛠️ Hardware Requirements

### Essential Components
- **ESP32 Dev Board** (with WiFi/BLE)
- **OLED Display** 128x64 (SSD1306, I2C)
- **Buzzer** (passive)
- **4 Buttons** (UP, DOWN, OK, MENU)
- **Breadboard & Jumper Wires**

### Pin Configuration
```cpp
#define SDA_PIN 6      // OLED SDA
#define SCL_PIN 5      // OLED SCL
#define BTN_UP 7       // Up button
#define BTN_DOWN 10    // Down button
#define BTN_OK 20      // OK/Select button
#define BTN_MENU 21    // Menu/Back button
#define BUZZER_PIN 2   // Buzzer
```

## 📦 Software Requirements

### Libraries
Install these via Arduino Library Manager:
- `Adafruit GFX Library`
- `Adafruit SSD1306`
- `Preferences`
- `BLEDevice` (ESP32 BLE Arduino)
- `WiFi` (Built-in)

### Platform
- **PlatformIO** (recommended) or **Arduino IDE**
- **ESP32 Board Support** (ESP32 Dev Module)

## 🚀 Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/smart-dolphin-hunter.git
cd smart-dolphin-hunter
```

### 2. PlatformIO Setup
```ini
; platformio.ini
[env:esp32dev]
platform = espressif32
board = esp32dev
framework = arduino
monitor_speed = 115200
lib_deps = 
    adafruit/Adafruit GFX Library@^1.11.7
    adafruit/Adafruit SSD1306@^2.5.7
```

### 3. Hardware Assembly
```
ESP32 Pinout:
GPIO5  → OLED SCL
GPIO6  → OLED SDA
GPIO7  → Button UP
GPIO10 → Button DOWN
GPIO20 → Button OK
GPIO21 → Button MENU
GPIO2  → Buzzer (+)
GND    → OLED GND, Buttons, Buzzer (-)
3.3V   → OLED VCC
```

### 4. Upload Code
```bash
pio run --target upload
# or use Arduino IDE
```

## 🎯 How to Use

### Basic Navigation
- **MENU Button**: Access main menu
- **OK Button**: Select/confirm
- **UP/DOWN**: Navigate menus
- **UP + DOWN**: Save progress
- **OK + MENU**: Force BLE scan

### Game Flow
1. **Startup**: New dolphin is born or load saved progress
2. **Auto-scanning**: Dolphin automatically scans WiFi/BLE periodically
3. **Pet Care**: Use UP button to feed, DOWN to play
4. **Evolve**: Gain XP by finding vulnerabilities
5. **Mood Management**: Keep dolphin happy to prevent attacks
6. **Stats Tracking**: Monitor progress in Statistics menu

### Menu Structure
```
MAIN MENU
├── Stats (Tabbed: General, Network, Security, Status)
├── History (Recent scans)
├── WiFi Setup (Connect to networks)
├── Settings (Configure behavior)
├── Save (Manual save)
└── Back
```

## 🔧 Configuration

### Settings (Saved in NVS)
```cpp
// Mood System
moodEnabled: true/false
moodAggressionThreshold: 70 (0-100)
attackCooldown: 300 (seconds)

// Scanning
scanInterval: 3 (minutes)
aggressiveScan: true/false
bleScanTime: 15 (seconds)

// Features
sleepEnabled: true/false
beepEnabled: true/false
activeProbe: true/false
```

### WiFi Configuration
- Auto-connects to saved open networks
- Manual setup via WiFi Setup menu
- Credentials stored securely in Preferences

## ⚠️ Safety & Ethics

### IMPORTANT DISCLAIMERS
1. **FOR EDUCATION ONLY**: This tool demonstrates security concepts
2. **LEGAL USE ONLY**: Only test your own devices/networks
3. **NO MALICIOUS INTENT**: Designed for security awareness
4. **RESPONSIBILITY**: You are responsible for your actions

### Built-in Safety Features
- **Private Network Check**: Attacks only allowed on private IPs (currently disabled, but feel free to enable it)
- **Confirmation Prompts**: User must confirm before attacks (just for limiting the damage)
- **Rate Limiting**: Cooldowns between attacks
- **Visual Warnings**: Clear warnings before any action

## 🐛 Known Issues & Limitations

### Technical Limitations
- **WiFi Monitor Mode**: Limited by ESP32 capabilities
- **BLE Range**: Typical BLE range (~10m)
- **Display**: 128x64 resolution limits UI complexity
- **Memory**: Limited heap space for large scans

### Features Not Included
- No packet injection beyond basic deauth
- No encryption cracking
- No persistence beyond saved WiFi
- No remote control/API

### Community Contributions
- Add new vulnerability patterns
- Improve animations
- Create custom themes
- Port to other displays

## 📚 Learning Resources

### Related Projects
- [ESP32 Marauder](https://github.com/justcallmekoko/ESP32Marauder)
- [WiFi Duck](https://github.com/SpacehuhnTech/WifiDuck)
- [BadUSB](https://github.com/Seytonic/Malduino)

### Security Education
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [HackTheBox](https://www.hackthebox.com/)
- [TryHackMe](https://tryhackme.com/)

## 👥 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Contribution Guidelines
- Follow existing code style
- Add comments for complex logic
- Update documentation
- Test thoroughly before PR

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2026 Smart Dolphin Hunter

Permission is hereby granted...
```

## 🙏 Acknowledgments

- **ESP32 Community** for amazing hardware support
- **Adafruit** for display libraries
- **Security Researchers** who share knowledge
- **Open Source Community** for inspiration

## 📞 Support

**For issues:**
1. Check [Issues](../../issues) for existing reports
2. Provide hardware details and error logs
3. Include reproduction steps

**Educational Use:**
- Perfect for cybersecurity workshops
- Great for understanding network protocols
- Excellent visual aid for security concepts

---

**Remember**: With great power comes great responsibility. Use this tool to learn and protect, not to harm. 🛡️

*Stay curious, stay ethical, and happy hunting!* 🐬
