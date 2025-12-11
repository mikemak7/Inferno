<context_iot_security>
## IoT & Embedded Device Security Assessment

### Target Types

**Network IoT Devices**:
- Smart TVs, cameras, doorbells
- Routers, access points, switches
- Smart home hubs, thermostats
- Industrial IoT (IIoT) devices

**Firmware Files**:
- .bin, .fw, .img, .rom, .hex, .elf
- SquashFS, JFFS2, UBIFS filesystems

**Memory Dumps**:
- .dmp, .dump, .mem, .raw, .vmem, .lime
- Live memory forensics

**Binaries**:
- .exe, .dll, .so, .dylib
- Mobile apps (.apk, .ipa)

### IoT Discovery & Enumeration

**Network Discovery**:
```bash
# Host discovery
nmap -sn 192.168.1.0/24

# IoT service ports
nmap -p 80,443,554,1883,5683,8080,8443,8883,47808 --open <target>

# UPnP discovery
upnpc -l
nmap --script=upnp-info <target>

# mDNS/Bonjour
avahi-browse -a
dns-sd -B _services._dns-sd._udp
```

**Common IoT Ports**:
| Port | Service | Description |
|------|---------|-------------|
| 80/443 | HTTP/S | Web interface |
| 554 | RTSP | Video streaming |
| 1883 | MQTT | Message broker |
| 5683 | CoAP | Constrained protocol |
| 8883 | MQTTS | Secure MQTT |
| 47808 | BACnet | Building automation |
| 502 | Modbus | Industrial control |
| 20000 | DNP3 | SCADA systems |

### Firmware Analysis

**Extraction**:
```bash
# Extract with binwalk
binwalk -e firmware.bin

# Identify filesystem
binwalk firmware.bin

# JFFS2 extraction
jefferson -d jffs2.img

# SquashFS extraction
sasquatch -p 1 squashfs.img -d output/

# UBIFS extraction
ubi_reader ubifs.img
```

**Secret Hunting**:
```bash
# In extracted filesystem
grep -r "password" ./extracted/
grep -r "api_key" ./extracted/
grep -r "secret" ./extracted/
find . -name "*.key" -o -name "*.pem"
find . -name "shadow" -o -name "passwd"
strings ./extracted/bin/* | grep -i pass
```

**Configuration Analysis**:
```bash
# Common config locations
./etc/config
./etc/passwd
./etc/shadow
./var/config
./www/*.conf
./usr/share/
```

### Protocol Testing

**MQTT**:
```bash
# Subscribe to all topics
mosquitto_sub -h <target> -t '#' -v

# System topics (info disclosure)
mosquitto_sub -h <target> -t '$SYS/#' -v

# Test publishing
mosquitto_pub -h <target> -t 'test' -m 'payload'
```

**CoAP**:
```bash
# Discover resources
coap-client -m get coap://<target>/.well-known/core

# Read resource
coap-client -m get coap://<target>/sensor/temp
```

**BLE (Bluetooth Low Energy)**:
```bash
# Scan for devices
hcitool lescan

# Connect and enumerate
gatttool -b <MAC> -I
> connect
> primary
> characteristics
> char-read-hnd <handle>
```

### Memory Forensics

**Volatility3 Analysis**:
```bash
# Identify OS
volatility3 -f memory.dmp windows.info
volatility3 -f memory.dmp linux.info

# Process list
volatility3 -f memory.dmp windows.pslist
volatility3 -f memory.dmp linux.psaux

# Network connections
volatility3 -f memory.dmp windows.netscan
volatility3 -f memory.dmp linux.sockstat

# Command history
volatility3 -f memory.dmp linux.bash
volatility3 -f memory.dmp windows.cmdline
```

**Secret Extraction**:
```bash
# String extraction
strings -n 8 memory.dmp > strings.txt
grep -iE "password|secret|key|token" strings.txt

# Bulk extraction
bulk_extractor -o output memory.dmp
```

### Reverse Engineering

**Static Analysis**:
```bash
# File identification
file binary
checksec --file=binary

# Strings analysis
strings binary | head -100

# Radare2
r2 -A binary
> afl              # List functions
> s main; pdf      # Disassemble main
> iz               # List strings
> /R password      # Search pattern
```

**Dangerous Functions**:
```bash
# Look for vulnerable patterns
objdump -d binary | grep -E "system|exec|popen|strcpy|gets|sprintf"
```

### Default Credentials

**IoT Device Defaults**:
| Vendor | Username | Password |
|--------|----------|----------|
| Generic | admin | admin |
| Generic | admin | password |
| Generic | root | root |
| Ubiquiti | ubnt | ubnt |
| Hikvision | admin | 12345 |
| Dahua | admin | admin |
| TP-Link | admin | admin |
| D-Link | admin | (blank) |
| Raspberry Pi | pi | raspberry |
| Samsung | (varies) | 0000 |

### Attack Priorities

1. **Default Credentials** - Most IoT never changes defaults
2. **Unauthenticated APIs** - Many expose REST/MQTT without auth
3. **Firmware Secrets** - Hardcoded creds, API keys, certs
4. **Command Injection** - Web interfaces often vulnerable
5. **Debug Interfaces** - UART, JTAG, SSH often left enabled
6. **Protocol Abuse** - MQTT publish, UPnP, SSDP reflection

### PoC Requirements

For every finding, create a standalone PoC script that:
- Connects to the target
- Demonstrates the vulnerability
- Shows extracted data or achieved access
- Includes clear success/failure output
</context_iot_security>
