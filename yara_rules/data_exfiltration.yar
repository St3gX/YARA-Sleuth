/*
    YARA-Sleuth Data Exfiltration & PII Detection Rules
    Author: St3gX
    Description: Detects sensitive data patterns and potential data exfiltration
*/

rule Credit_Card_Data {
    meta:
        description = "Detects credit card number patterns in files"
        severity = "HIGH"
        category = "pii"
        author = "YARA-Sleuth"
    strings:
        // Visa
        $visa = /4[0-9]{15}/
        // MasterCard
        $mc = /5[1-5][0-9]{14}/
        // Amex
        $amex = /3[47][0-9]{13}/
        // Discover
        $discover = /6011[0-9]{12}/
        $cc_keyword = "credit_card" nocase
        $cc_keyword2 = "card_number" nocase
    condition:
        (any of ($visa,$mc,$amex,$discover)) or (2 of ($cc_keyword*))
}

rule Social_Security_Number {
    meta:
        description = "Detects US Social Security Number patterns"
        severity = "HIGH"
        category = "pii"
        author = "YARA-Sleuth"
    strings:
        $ssn = /[0-9]{3}-[0-9]{2}-[0-9]{4}/
        $ssn_kw = "social_security" nocase
        $ssn_kw2 = "SSN" fullword
    condition:
        $ssn or any of ($ssn_kw*)
}

rule Data_Exfiltration_Script {
    meta:
        description = "Detects scripts with potential data exfiltration capabilities"
        severity = "CRITICAL"
        category = "exfiltration"
        author = "YARA-Sleuth"
    strings:
        $exfil1 = "curl -X POST" nocase
        $exfil2 = "wget --post-data" nocase
        $exfil3 = "requests.post" nocase
        $exfil4 = "ftp.storbinary" nocase
        $exfil5 = "smtplib.SMTP" nocase
        $sensitive1 = "/etc/passwd" nocase
        $sensitive2 = "/etc/shadow" nocase
        $sensitive3 = "id_rsa" nocase
        $sensitive4 = ".ssh" nocase
        $sensitive5 = "credentials" nocase
    condition:
        any of ($exfil*) and any of ($sensitive*)
}

rule Email_Address_Harvester {
    meta:
        description = "Detects email address harvesting patterns"
        severity = "MEDIUM"
        category = "pii"
        author = "YARA-Sleuth"
    strings:
        $email_regex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/
        $harvest1 = "email_list" nocase
        $harvest2 = "extract_emails" nocase
        $harvest3 = "scrape_emails" nocase
    condition:
        (#email_regex > 10) or any of ($harvest*)
}

rule Suspicious_API_Keys {
    meta:
        description = "Detects hardcoded API keys and tokens"
        severity = "HIGH"
        category = "secret_exposure"
        author = "YARA-Sleuth"
    strings:
        $aws1 = /AKIA[0-9A-Z]{16}/
        $gcp1 = "AIzaSy" nocase
        $token1 = "api_key" nocase
        $token2 = "secret_key" nocase
        $token3 = "access_token" nocase
        $token4 = "private_key" nocase
        $token5 = "BEGIN RSA PRIVATE KEY"
        $token6 = "BEGIN OPENSSH PRIVATE KEY"
    condition:
        $aws1 or $gcp1 or $token5 or $token6 or (3 of ($token*))
}
