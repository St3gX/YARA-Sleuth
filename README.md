# YARA-Sleuth 🔍
### Advanced File System Scanner for Digital Forensics by St3gX

A modular, multi-threaded digital forensics engine designed to detect malware indicators and data exfiltration artifacts using advanced YARA pattern matching and file entropy analysis.

Note: The reports/ directory is generated automatically during the first scan. It is excluded from the repository via .gitignore to ensure data privacy and prevent the accidental upload of forensic artifacts.
---

## 📁 Project Structure

```
yara_sleuth/
├── yara_sleuth.py          # Main scanner engine
├── requirements.txt        # Python dependencies
├── yara_rules/             # YARA rule sets
│   ├── binary_malware.yar
│   ├── malware_detection.yar
│   ├── suspicious_files.yar
│   └── data_exfiltration.yar
├── sample_files/           # Test files (simulated)
│   ├── sample_malware_sim.py
│   ├── clean_app.py
│   └── sql_payloads.txt
└── reports/                # Generated scan reports (auto-created)
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

### `binary_malware.yar`
- Identifies Windows PE and Linux ELF executable headers.
- Detects packed or obfuscated binaries (UPX, Themida, ASPack).
- Flags compiled ransomware, Trojans, and Info-Stealer indicators.
- Identifies anti-analysis and anti-VM evasion techniques.
- Detects embedded shellcode (NOP sleds) and worm propagation behavior.

### `malware_detection.yar`
- Detects suspicious shell command execution (PowerShell, bash).
- Flags ransomware behavior indicators and cryptocurrency addresses.
- Identifies Trojan, RAT, and backdoor behavioral patterns.
- Detects credential harvesting and memory-dumping strings (e.g., Mimikatz).
- Flags Base64-encoded obfuscated payloads and rootkit indicators.

### `data_exfiltration.yar`
- Detects hardcoded PII including Credit Card patterns and SSNs.
- Identifies data exfiltration scripts using web requests to external servers.
- Flags mass email harvesting and scraping patterns.
- Detects exposed API keys and private secrets (AWS, GCP, RSA keys).

### `suspicious_files.yar`
- Flags suspicious Python operations (`eval`, `exec`, `subprocess`).
- Identifies hidden executables nested within archives or misnamed extensions.
- Detects Windows registry persistence manipulation (`Run` keys).
- Flags network reconnaissance tools and SQL injection payloads.
- Identifies cryptocurrency mining indicators and potential compression bombs.

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
