# YARA-Sleuth 🔍
### Advanced File System Scanner for Digital Forensics by St3gX

A professional-grade forensics tool built in Python that uses **YARA rules** to
detect malware, suspicious files, credential leaks, data exfiltration artifacts,
and security threats across a file system.

---

## 📁 Project Structure

```
yara_sleuth/
├── yara_sleuth.py           # Main scanner engine
├── requirements.txt         # Python dependencies
├── yara_rules/              # YARA rule sets
│   ├── malware_detection.yar
│   ├── suspicious_files.yar
│   └── data_exfiltration.yar
├── sample_files/            # Test files (simulated)
│   ├── sample_malware_sim.py
│   ├── clean_app.py
│   └── sql_payloads.txt
└── reports/                 # Generated scan reports (auto-created)
```

---

## ⚙️ Installation

```bash
pip install -r requirements.txt
```

---

## 🚀 Usage

```bash
# Basic scan
python yara_sleuth.py --target ./sample_files

# Scan entire directory recursively
python yara_sleuth.py --target /home/user/Documents

# Use custom rule directory
python yara_sleuth.py --target ./suspicious_dir --rules ./custom_rules

# Non-recursive scan (current directory only)
python yara_sleuth.py --target ./folder --no-recursive

# Skip JSON report
python yara_sleuth.py --target ./folder --no-json
```

---

## 🧩 Architecture

| Component         | Class              | Responsibility                              |
|-------------------|--------------------|---------------------------------------------|
| Rule Loader       | `RuleLoader`       | Compiles all `.yar` files into memory        |
| File Metadata     | `FileMetadata`     | Extracts MD5, SHA-256, timestamps, perms    |
| YARA Scanner      | `YARAScanner`      | Matches rules against file content          |
| FS Walker         | `FileSystemWalker` | Recursive traversal with live spinner       |
| Report Generator  | `ReportGenerator`  | Colored terminal + JSON + text reports      |
| Orchestrator      | `YARASleuth`       | Ties all components together                |

---

## 📋 YARA Rule Sets

### `malware_detection.yar`
- Suspicious shell command execution
- Ransomware indicators
- Trojan/backdoor patterns
- Credential harvesting
- Base64-encoded payloads
- Rootkit indicators

### `suspicious_files.yar`
- Suspicious Python scripts
- Hidden executables (PE/ELF headers)
- Registry manipulation
- Network scanning tools
- SQL injection payloads
- Crypto-mining indicators

### `data_exfiltration.yar`
- Credit card number patterns (PCI-DSS)
- Social Security Numbers
- Data exfiltration scripts
- Email harvesting
- Exposed API keys & private keys

---

## 📊 Output

**Terminal Output** — Color-coded by severity (CRITICAL / HIGH / MEDIUM / LOW)  
**JSON Report** — Full structured output in `reports/yara_sleuth_TIMESTAMP.json`  
**Text Report** — Human-readable report in `reports/yara_sleuth_TIMESTAMP.txt`

---

## 🔧 Adding Custom Rules

Create a `.yar` file in the `yara_rules/` folder:

```yara
rule My_Custom_Rule {
    meta:
        description = "My detection rule"
        severity = "HIGH"
        category = "custom"
        author = "Your Name"
    strings:
        $s1 = "suspicious_string" nocase
    condition:
        any of them
}
```

---

## ⚠️ Disclaimer

This tool is intended for **educational and authorized forensics use only**.
Always obtain proper authorization before scanning systems you do not own.
