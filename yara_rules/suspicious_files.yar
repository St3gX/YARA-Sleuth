/*
    YARA-Sleuth Suspicious File Pattern Rules
    Author: St3gX
    Description: Detects suspicious file structures, headers, and patterns
*/

rule Suspicious_Python_Script {
    meta:
        description = "Detects suspicious Python scripts with dangerous operations"
        severity = "MEDIUM"
        category = "suspicious_script"
        author = "YARA-Sleuth"
    strings:
        $py1 = "import os" nocase
        $py2 = "import subprocess" nocase
        $py3 = "import socket" nocase
        $py4 = "exec(" nocase
        $py5 = "eval(" nocase
        $py6 = "__import__" nocase
    condition:
        (#py4 > 2) or (#py5 > 2) or (($py1 or $py2 or $py3) and ($py4 or $py5 or $py6))
}

rule Hidden_Executable_in_Archive {
    meta:
        description = "Detects executable files with misleading extensions"
        severity = "HIGH"
        category = "evasion"
        author = "YARA-Sleuth"
    strings:
        $mz_header = { 4D 5A }       // PE/MZ header
        $elf_header = { 7F 45 4C 46 } // ELF header
    condition:
        ($mz_header at 0) or ($elf_header at 0)
}

rule Suspicious_Registry_Manipulation {
    meta:
        description = "Detects suspicious Windows registry manipulation"
        severity = "HIGH"
        category = "persistence"
        author = "YARA-Sleuth"
    strings:
        $reg1 = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $reg2 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $reg3 = "RegSetValueEx" nocase
        $reg4 = "RegCreateKey" nocase
        $reg5 = "winreg" nocase
    condition:
        ($reg1 or $reg2) and ($reg3 or $reg4 or $reg5)
}

rule Network_Scanning_Tool {
    meta:
        description = "Detects network scanning and reconnaissance tools"
        severity = "MEDIUM"
        category = "reconnaissance"
        author = "YARA-Sleuth"
    strings:
        $net1 = "port_scan" nocase
        $net2 = "nmap" nocase
        $net3 = "syn_flood" nocase
        $net4 = "ping_sweep" nocase
        $net5 = "socket.SOCK_RAW" nocase
        $net6 = "ICMP" nocase
        $net7 = "scapy" nocase
    condition:
        3 of them
}

rule SQL_Injection_Payload {
    meta:
        description = "Detects SQL injection payloads in files"
        severity = "MEDIUM"
        category = "web_attack"
        author = "YARA-Sleuth"
    strings:
        $sql1 = "' OR '1'='1" nocase
        $sql2 = "' OR 1=1--" nocase
        $sql3 = "UNION SELECT" nocase
        $sql4 = "DROP TABLE" nocase
        $sql5 = "1'; DROP TABLE" nocase
        $sql6 = "xp_cmdshell" nocase
    condition:
        any of them
}

rule Crypto_Mining_Indicators {
    meta:
        description = "Detects cryptocurrency mining software signatures"
        severity = "MEDIUM"
        category = "cryptominer"
        author = "YARA-Sleuth"
    strings:
        $mine1 = "stratum+tcp://" nocase
        $mine2 = "mining_pool" nocase
        $mine3 = "monero" nocase
        $mine4 = "xmrig" nocase
        $mine5 = "hashrate" nocase
        $mine6 = "wallet_address" nocase
        $mine7 = "coinhive" nocase
    condition:
        2 of them
}

rule Suspicious_Compression_Bomb {
    meta:
        description = "Detects potential compression bomb or zip bomb indicators"
        severity = "HIGH"
        category = "dos"
        author = "YARA-Sleuth"
    strings:
        $zip_header = { 50 4B 03 04 }
        $bomb_indicator = "zipbomb" nocase
        $large_ratio = "compression_ratio" nocase
    condition:
        $zip_header and ($bomb_indicator or $large_ratio)
}
