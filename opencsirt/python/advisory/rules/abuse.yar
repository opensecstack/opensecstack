/*
 * YARA rule-set for OpenCSIRT abuse-mailbox triage.
 *
 * Rules are intentionally narrow — false positives on a triage queue
 * cost an analyst a click; false negatives just mean a manual review.
 * Every rule names the abuse_mail.py classification it influences.
 */

rule Phishing_Credential_Form
{
    meta:
        description = "Inline credential-harvest HTML form"
        classification = "phishing"
        author = "opencsirt"
    strings:
        $form    = /<form[^>]+action\s*=\s*["'][^"']+["'][^>]*>/i
        $passwd  = /<input[^>]+type\s*=\s*["']?password/i
        $brand1  = "microsoft" nocase
        $brand2  = "office365" nocase
        $brand3  = "paypal" nocase
        $brand4  = "docusign" nocase
        $brand5  = "google" nocase
    condition:
        $form and $passwd and 1 of ($brand*)
}

rule Phishing_Url_Shortener
{
    meta:
        description = "URL-shortener domain combined with urgency language"
        classification = "phishing"
    strings:
        $sh1 = "bit.ly/" nocase
        $sh2 = "tinyurl.com/" nocase
        $sh3 = "t.co/" nocase
        $sh4 = "is.gd/" nocase
        $u1  = "verify your account" nocase
        $u2  = "suspended" nocase
        $u3  = "urgent action required" nocase
        $u4  = "confirm your identity" nocase
    condition:
        1 of ($sh*) and 1 of ($u*)
}

rule Malware_Office_Macro_Hint
{
    meta:
        description = "Office attachment with macro-typical filename"
        classification = "malware"
    strings:
        $a = "Content-Disposition: attachment" nocase
        $f1 = /filename="[^"]+\.(docm|xlsm|xltm|pptm|dotm)"/i
        $f2 = /filename="invoice[_\-]?\d*\.(doc|xls|pdf)"/i
    condition:
        $a and ($f1 or $f2)
}

rule Malware_Encoded_Executable
{
    meta:
        description = "MZ header in a base64 attachment"
        classification = "malware"
    strings:
        // Base64 of "MZ" preceded by a newline → "TVqQAAMAAAAEAAAA..." prefix
        $b64_mz = /\n[ \t]*TVqQ[A-Za-z0-9+\/]{20,}/
    condition:
        $b64_mz
}

rule Scam_Advance_Fee
{
    meta:
        description = "419-style advance-fee fraud language"
        classification = "scam"
    strings:
        $a = "transfer the sum" nocase
        $b = "next of kin" nocase
        $c = "lottery" nocase
        $d = "beneficiary" nocase
        $e = "western union" nocase
        $f = "bitcoin wallet" nocase
    condition:
        2 of them
}

rule Legitimate_Vendor_Bulletin
{
    meta:
        description = "Markers commonly present on legitimate vendor advisories"
        classification = "legitimate"
    strings:
        $cve = /CVE-\d{4}-\d{4,}/
        $vendor1 = "security@" nocase
        $vendor2 = "psirt@" nocase
        $vendor3 = "Subject: Security Advisory" nocase
    condition:
        $cve and 1 of ($vendor*)
}
