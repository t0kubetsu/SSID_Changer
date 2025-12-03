# **SSIDChanger – PCAP Wi-Fi SSID Modifier**

`SSIDChanger` is a Python tool that parses a `.pcap` file, identifies Wi-Fi **Beacon** and **Probe Response** frames, and interactively allows you to rename their SSIDs.
This is useful for anonymizing wireless captures before sharing them (e.g., in CTI, DFIR, training, or CTF challenge development).

The tool uses **Scapy** to read and write packets and ensures modified packets preserve structure and length.

## ✨ **Features**

* Extracts and modifies SSIDs from:
  * `Dot11Beacon`
  * `Dot11ProbeResp`
* Interactive SSID replacement prompt
* Optional exclusion list (skip selected SSIDs)

## 📦 **Requirements**

* Python **3.8+**
* Scapy

Install dependencies:

```bash
pip install scapy
```

## 🧰 **Usage**

### **Basic example**

```bash
python main.py -f my_capture.pcap
```

You'll be prompted for each SSID detected.

### **Exclude specific SSIDs**

Skip modifying specific SSIDs:

```bash
python main.py -f my_capture.pcap -e 'Don't touch me'
```

### **Specify output filename**

```bash
python main.py -f my_capture.pcap -o cleaned_capture.pcap
```

## ⚙️ **Command-line Arguments**

| Argument          | Description                          |
| ----------------- | ------------------------------------ |
| `-f`, `--file`    | **(Required)** Input pcap file       |
| `-e`, `--exclude` | SSID names to skip (space-separated) |
| `-o`, `--output`  | Optional output pcap filename        |

Example:

```bash
python main.py -f my_capture.pcap -e HomeWifi CorpNet IoT -o sanitized.pcap
```
