rule Suspicious_Packer_UPX {
  meta:
    description = "Detects common UPX packer section markers"
    severity = "medium"
  strings:
    $upx0 = "UPX0" ascii wide nocase
    $upx1 = "UPX1" ascii wide nocase
    $upx2 = "UPX2" ascii wide nocase
  condition:
    any of them
}

rule Suspicious_Ransomware_Note {
  meta:
    description = "Detects strings commonly found in ransom notes"
    severity = "high"
  strings:
    $a = "your files have been encrypted" ascii wide nocase
    $b = "decrypt your files" ascii wide nocase
    $c = "pay the ransom" ascii wide nocase
    $d = "bitcoin wallet" ascii wide nocase
  condition:
    2 of them
}

rule Suspicious_Process_Injection_APIs {
  meta:
    description = "Detects process injection API names"
    severity = "medium"
  strings:
    $a = "VirtualAllocEx" ascii wide
    $b = "WriteProcessMemory" ascii wide
    $c = "CreateRemoteThread" ascii wide
    $d = "NtWriteVirtualMemory" ascii wide
  condition:
    2 of them
}

rule Suspicious_Anti_Debug {
  meta:
    description = "Detects anti-debugging API names"
    severity = "low"
  strings:
    $a = "IsDebuggerPresent" ascii wide
    $b = "CheckRemoteDebuggerPresent" ascii wide
    $c = "NtQueryInformationProcess" ascii wide
  condition:
    2 of them
}

rule Suspicious_Network_Indicators {
  meta:
    description = "Detects network download and command execution strings"
    severity = "medium"
  strings:
    $a = "URLDownloadToFile" ascii wide
    $b = "WinHttpOpen" ascii wide
    $c = "InternetOpenUrl" ascii wide
    $d = "powershell -enc" ascii wide nocase
  condition:
    2 of them
}

rule Suspicious_Registry_Persistence {
  meta:
    description = "Detects Windows Run-key persistence strings and registry APIs"
    severity = "medium"
  strings:
    $a = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
    $b = "RegSetValueEx" ascii wide
    $c = "RegCreateKeyEx" ascii wide
  condition:
    2 of them
}
