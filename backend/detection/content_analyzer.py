import re
import os
from pathlib import Path
from typing import Dict, List, Tuple, Any
import json


class ContentAnalyzer:
    """
    Analyzes file contents for malicious patterns across different file types.
    Enhanced with ransomware-specific detection patterns.
    """
    
    # High-risk patterns for batch files (cmd.exe, .bat, .cmd)
    BATCH_MALICIOUS_PATTERNS = [
        # System destruction patterns
        (r'del /f /s /q .*system32', 'Attempts to delete System32 files', 90),
        (r'rmdir /s /q .*system32', 'Removes System32 directory', 95),
        (r'format .* /q', 'Format command - potential disk wipe', 100),
        (r'cipher /w:', 'Secure deletion - data destruction', 85),
        (r'deltree /y', 'Legacy directory deletion', 80),
        
        # Registry manipulation (dangerous)
        (r'reg delete .* /f', 'Force registry deletion', 85),
        (r'reg add .* /f', 'Force registry addition', 70),
        (r'reg import .*\.reg', 'Registry import - could modify security settings', 75),
        
        # System compromise
        (r'net user .* \/add', 'Creates new user account', 85),
        (r'net localgroup administrators .* \/add', 'Adds user to admin group', 95),
        (r'runas \/user:administrator', 'Attempts privilege escalation', 90),
        
        # Disabling security
        (r'netsh advfirewall set .* state off', 'Disables Windows Firewall', 90),
        (r'sc stop .* (?:defender|security|avast|mcafee)', 'Stops security services', 90),
        (r'taskkill /f /im .* (?:defender|av|security)', 'Kills security processes', 90),
        
        # Data exfiltration
        (r'ftp .* -s:', 'FTP script - potential data exfiltration', 80),
        (r'powershell.*Invoke-WebRequest.*-OutFile', 'Downloads file from internet', 70),
        
        # Persistence
        (r'reg add .*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', 'Adds to startup registry', 75),
        (r'schtasks \/create', 'Creates scheduled task - persistence', 80),
        
        # Bypass mechanisms
        (r'powershell.*-ExecutionPolicy Bypass', 'Bypass PowerShell execution policy', 85),
        (r'powershell.*-EncodedCommand', 'Encoded PowerShell command - often malicious', 90),
        
        # Ransomware-specific patterns
        (r'Get-Process.*Kill', 'Process termination capability', 75),
        (r'Stop-Process', 'Stops processes - potential data destruction', 80),
        (r'Remove-Item.*-Recurse', 'Recursive file deletion', 85),
        
        # System tool manipulation (Early stage)
        (r'vssadmin.*delete.*shadows', 'Deleting Shadow Copies', 95),
        (r'wbadmin.*delete.*catalog', 'Deleting backup catalog', 95),
        (r'bcdedit.*/set.*recoveryenabled', 'Disabling recovery', 90),
    ]
    
    # PowerShell specific patterns
    PS_MALICIOUS_PATTERNS = [
        (r'Invoke-Command.*-ComputerName', 'Remote command execution', 85),
        (r'Invoke-Expression.*\(.*\)', 'Dynamic code execution', 80),
        (r'\[System\.Reflection\.Assembly\]::Load', 'Assembly injection', 90),
        (r'Add-Type -AssemblyName.*System\.Management', 'Management API access', 75),
        (r'Get-WmiObject.*Win32_Process', 'Process manipulation via WMI', 70),
        (r'Start-Process.*-Verb runAs', 'Privilege escalation attempt', 90),
        (r'Set-MpPreference.*-Disable', 'Disables Windows Defender', 95),
        (r'Add-MpPreference.*-ExclusionPath', 'Adds Defender exclusion', 80),
        # Ransomware-specific
        (r'Get-ChildItem.*-Recurse.*\|.*Remove-Item', 'Mass file deletion', 90),
        (r'Remove-Item.*-Force.*-Recurse', 'Force recursive deletion', 85),
        (r'Get-Process.*Stop-Process', 'Stops multiple processes', 80),
        (r'\[System\.IO\.File\]::ReadAllBytes', 'Reads file contents - potential encryption prep', 75),
        (r'\[System\.IO\.File\]::WriteAllBytes', 'Writes file contents - potential encryption', 80),
        (r'Encrypt', 'Encryption operation', 85),
        (r'Decrypt', 'Decryption operation', 70),
        # Early stage system tools
        (r'vssadmin.*delete.*shadows', 'Deleting Shadow Copies', 95),
        (r'wbadmin.*delete.*catalog', 'Deleting backup catalog', 95),
        (r'bcdedit.*/set.*recoveryenabled', 'Disabling recovery', 90),
    ]
    
    # VBScript patterns
    VBS_MALICIOUS_PATTERNS = [
        (r'CreateObject\("WScript\.Shell"\)\.Run', 'Shell command execution', 80),
        (r'CreateObject\("Scripting\.FileSystemObject"\)\.DeleteFile', 'File deletion', 85),
        (r'\.DeleteFolder\(', 'Folder deletion', 85),
        (r'\.RegWrite', 'Registry write operation', 75),
        # Ransomware-specific
        (r'Set oFSO.*CreateTextFile', 'Creates files - could be encryption', 70),
        (r'\.CopyFile', 'File copying - could be backup before encryption', 60),
    ]
    
    # Linux shell script patterns
    BASH_MALICIOUS_PATTERNS = [
        (r'rm\s+-rf\s+/\s*$', 'Attempts to delete root directory', 100),
        (r':\(\)\{.*:\|:&\};:', 'Fork bomb', 100),
        (r'chmod\s+777\s+/etc', 'Opens permissions on system files', 90),
        (r'>\s*/dev/sda', 'Direct disk write - potential data destruction', 95),
        # Ransomware-specific
        (r'openssl\s+enc\s+-', 'File encryption using OpenSSL', 85),
        (r'gpg\s+--encrypt', 'File encryption using GPG', 80),
        (r'chattr\s+-i', 'Removes immutable attribute', 75),
    ]

    # Python-specific malicious patterns
    PYTHON_MALICIOUS_PATTERNS = [
        # Crypto/currency patterns
        (r'bitcoin|btc|monero|xmr', 'Cryptocurrency-related code', 30),
        (r'ransom', 'Ransomware-related term', 40),
        # Encryption patterns
        (r'def\s+encrypt', 'Encryption function definition', 75),
        (r'def\s+decrypt', 'Decryption function definition', 75),
        (r'from\s+Crypto|import\s+Crypto', 'Crypto library usage', 70),
        (r'from\s+cryptography|import\s+cryptography', 'Cryptography library usage', 70),
        (r'\.encrypt\(|\.decrypt\(', 'Encryption/decryption method calls', 80),
        # File manipulation patterns
        (r'os\.walk', 'Directory traversal - enumerate files', 60),
        (r'\.encrypted', 'Encrypted file extension', 85),
        (r'\.bak', 'Backup file creation', 50),
        # Network/exfiltration
        (r'urllib|requests\.get|httpx', 'HTTP network requests', 55),
        (r'tor|onion', 'Tor network usage', 35),
        # Process manipulation
        (r'subprocess\.run|subprocess\.call', 'Execute system commands', 70),
        (r'os\.system\(|os\.popen', 'Direct system command execution', 75),
        (r'psutil', 'Process enumeration library', 65),
        # Key generation
        (r'random\.choice.*string', 'Random key generation', 70),
        (r'\.xor|xor.*data', 'XOR encryption', 85),
    ]
    
    # Ransomware file extension patterns (suspicious new extensions)
    RANSOMWARE_EXTENSIONS = [
        '.encrypted', '.locked', '.crypto', '.crypt', '.enc', '.ransom',
        '.locked', '.key', '.aes', '.RSA', '.mbed', '.infy', '.cerber',
        '.locky', '.cryptolocker', '.wannacry', '.petya', '.notpetya'
    ]
    
    # Critical patterns that trigger immediate high risk without division
    CRITICAL_PATTERNS = [
        # System recovery destruction (Ransomware preparation)
        (r'vssadmin.*delete.*shadows', 'Deleting Shadow Copies (Ransomware Preparation)', 95),
        (r'wbadmin.*delete.*catalog', 'Deleting Backup Catalog (Ransomware Preparation)', 95),
        (r'bcdedit.*/set.*recoveryenabled.*no', 'Disabling System Recovery', 90),
        (r'Set-MpPreference.*-Disable', 'Disabling Windows Defender', 95),
        # Ransom note patterns
        (r'your files (have been|are) encrypted', 'Classic ransom note opening - files encrypted', 95),
        (r'send .{0,30}bitcoin', 'Bitcoin payment demand in ransom note', 90),
        (r'to (recover|restore|decrypt) your files', 'File recovery demand - ransom note', 85),
        (r'contact .{0,40}(tor|onion|darkweb)', 'Tor/dark web contact for ransom payment', 90),
        (r'unique (decrypt|decryption) key', 'Unique decryption key - typical ransom note', 85),
        (r'bitcoin.*payment', 'Bitcoin payment instruction', 90),
        (r'(ransom|decrypt).*(bitcoin|btc|monero|xmr)', 'Cryptocurrency ransom demand', 95),
        (r'pay.*(within|before).*(hours|days|deadline)', 'Payment deadline threat', 85),
    ]

    # Suspicious file operations and system tool usage
    SUSPICIOUS_OPERATIONS = [
        # Ransomware file behavior
        (r'Rename-Item.*\.encrypted', 'File renaming to encrypted extension', 90),
        (r'Rename-Item.*\.locked', 'File renaming to locked extension', 90),
        (r'\.Move.*\.enc', 'Moving to .enc extension', 85),
        (r'Get-ChildItem.*\.txt\|.*Remove', 'Deleting all text files', 95),
        
        # System backup and recovery destruction (Early Stage Indicators)
        (r'vssadmin.*delete.*shadows', 'Attempting to delete Shadow Copies (prevents file recovery)', 95),
        (r'wbadmin.*delete.*catalog', 'Deleting system backup catalog', 95),
        (r'bcdedit.*/set.*recoveryenabled.*no', 'Disabling Windows Recovery environment', 90),
        (r'bcdedit.*/set.*bootstatuspolicy.*ignoreallfailures', 'Suppressing boot error messages', 85),
        (r'cipher.*/w:', 'Wiping free disk space (secure deletion)', 80),
        (r'netsh.*advfirewall.*off', 'Disabling firewall via netsh', 90),
    ]

    # Ransomware source code patterns (for .c, .cpp, .py, .js, etc.)
    RANSOMWARE_CODE_PATTERNS = [
        # File encryption patterns
        (r'EncryptFile', 'File encryption function', 85),
        (r'CryptEncrypt', 'Windows Crypto API encryption', 90),
        (r'CryptDecrypt', 'Windows Crypto API decryption', 85),
        (r'RC4_Encrypt|rc4_encrypt', 'RC4 encryption implementation', 80),
        (r'AES_(Encrypt|Decrypt)', 'AES encryption/decryption', 80),
        (r'RSA_(Encrypt|Decrypt)', 'RSA encryption/decryption', 85),
        # File deletion/backup prevention
        (r'ShadowCopyDelete|delete.*shadow', 'Shadow copy deletion code', 95),
        (r'CreateProcess.*cmd\.exe.*vssadmin', 'Creates process to delete shadows', 95),
        (r'System\(.*vssadmin', 'Executes vssadmin command', 90),
        # Network/exfiltration
        (r'SendKeys|socket.*send', 'Keylogging or data exfiltration', 85),
        (r'Bitcoin|bitcoin|wallet.*address', 'Bitcoin/wallet address handling', 80),
        # Process termination
        (r'TerminateProcess.*explorer', 'Terminates explorer process', 85),
        (r'KillProcess|process.*kill', 'Process killing capability', 80),
    ]
    
    @classmethod
    def analyze_file(cls, file_path: str) -> Dict[str, Any]:
        """
        Main entry point - analyzes any file and returns risk assessment.
        """
        path = Path(file_path)
        
        # Check for ransomware extension (already encrypted files)
        if path.suffix.lower() in cls.RANSOMWARE_EXTENSIONS:
            return {
                "analysis_type": "ransomware_extension",
                "risk_score": 100,
                "findings": [{
                    "description": f"File has ransomware-associated extension: {path.suffix}",
                    "severity": 100
                }],
                "file_type": "encrypted",
                "risk_level": "CRITICAL"
            }
        
        # Skip if not a text file (for binary files, rely on entropy + ML)
        if not cls._is_text_file(file_path):
            return {
                "analysis_type": "binary",
                "risk_score": None,
                "findings": [],
                "file_type": "binary"
            }
        
        # Try to read file content
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            return {
                "analysis_type": "unreadable",
                "risk_score": 0,
                "findings": [f"Could not read file content: {str(e)}"],
                "file_type": "unknown"
            }
        
        # Determine file type and analyze accordingly
        file_ext = path.suffix.lower()
        
        if file_ext in ['.bat', '.cmd']:
            return cls._analyze_batch_file(content, file_path)
        elif file_ext in ['.ps1', '.psm1']:
            return cls._analyze_powershell_file(content, file_path)
        elif file_ext in ['.vbs', '.vbe']:
            return cls._analyze_vbs_file(content, file_path)
        elif file_ext in ['.sh', '.bash']:
            return cls._analyze_bash_file(content, file_path)
        elif file_ext in ['.py', '.pyw']:
            return cls._analyze_python_file(content, file_path)
        else:
            # Generic text file analysis
            return cls._analyze_generic_text(content, file_path)
    
    @classmethod
    def _is_text_file(cls, file_path: str, sample_size: int = 1024) -> bool:
        """Check if file appears to be text-based"""
        try:
            with open(file_path, 'rb') as f:
                sample = f.read(sample_size)
            # If no null bytes and mostly printable, it's likely text
            return b'\x00' not in sample and all(b >= 32 or b in (9, 10, 13) for b in sample[:100])
        except:
            return False
    
    @classmethod
    def _analyze_batch_file(cls, content: str, file_path: str) -> Dict[str, Any]:
        """Analyze batch file for malicious patterns"""
        findings = []
        risk_score = 0
        
        lines = content.split('\n')
        
        # Check for system32 deletion regardless of path format
        if re.search(r'del.*system32|rmdir.*system32|rd.*system32', content, re.IGNORECASE):
            findings.append({
                "line": 1,
                "code": "Attempts to delete System32",
                "description": "Malicious batch file targeting System32",
                "severity": 95
            })
            risk_score = 95
        
        # Check against known patterns
        for pattern, description, severity in cls.BATCH_MALICIOUS_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                findings.append({
                    "line": line_num,
                    "code": match.group()[:80],
                    "description": description,
                    "severity": severity
                })
                risk_score = max(risk_score, severity)
        
        # Check for critical patterns (no division)
        for pattern, description, severity in cls.CRITICAL_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                findings.append({"description": description, "severity": severity})
                risk_score = max(risk_score, severity)
        
        # Check for suspicious operations
        for pattern, description, severity in cls.SUSPICIOUS_OPERATIONS:
            if re.search(pattern, content, re.IGNORECASE):
                findings.append({
                    "description": description,
                    "severity": severity
                })
                risk_score = max(risk_score, severity)
        
        return {
            "analysis_type": "batch",
            "risk_score": min(100, risk_score),
            "findings": findings,
            "file_type": "batch",
            "risk_level": cls._get_risk_level(risk_score)
        }
    
    @classmethod
    def _analyze_powershell_file(cls, content: str, file_path: str) -> Dict[str, Any]:
        """Analyze PowerShell script"""
        findings = []
        risk_score = 0
        
        lines = content.split('\n')
        
        for pattern, description, severity in cls.PS_MALICIOUS_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                findings.append({
                    "line": line_num,
                    "code": match.group()[:80],
                    "description": description,
                    "severity": severity
                })
                risk_score = min(100, risk_score + severity // 3)
        
        # Check for critical patterns (no division)
        for pattern, description, severity in cls.CRITICAL_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                findings.append({"description": description, "severity": severity})
                risk_score = max(risk_score, severity)
        
        # Check for suspicious operations
        for pattern, description, severity in cls.SUSPICIOUS_OPERATIONS:
            if re.search(pattern, content, re.IGNORECASE):
                findings.append({
                    "description": description,
                    "severity": severity
                })
                risk_score = min(100, risk_score + severity // 4)
        
        return {
            "analysis_type": "powershell",
            "risk_score": min(100, risk_score),
            "findings": findings,
            "file_type": "powershell",
            "risk_level": cls._get_risk_level(risk_score)
        }
    
    @classmethod
    def _analyze_vbs_file(cls, content: str, file_path: str) -> Dict[str, Any]:
        """Analyze VBScript file"""
        findings = []
        risk_score = 0
        
        for pattern, description, severity in cls.VBS_MALICIOUS_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                findings.append({
                    "line": line_num,
                    "code": match.group()[:80],
                    "description": description,
                    "severity": severity
                })
                risk_score = min(100, risk_score + severity // 3)
        
        return {
            "analysis_type": "vbscript",
            "risk_score": min(100, risk_score),
            "findings": findings,
            "file_type": "vbscript",
            "risk_level": cls._get_risk_level(risk_score)
        }
    
    @classmethod
    def _analyze_bash_file(cls, content: str, file_path: str) -> Dict[str, Any]:
        """Analyze Bash shell script"""
        findings = []
        risk_score = 0
        
        for pattern, description, severity in cls.BASH_MALICIOUS_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                findings.append({
                    "line": line_num,
                    "code": match.group()[:80],
                    "description": description,
                    "severity": severity
                })
                risk_score = min(100, risk_score + severity // 3)
        
        # Check for suspicious operations
        for pattern, description, severity in cls.SUSPICIOUS_OPERATIONS:
            if re.search(pattern, content, re.IGNORECASE):
                findings.append({
                    "description": description,
                    "severity": severity
                })
                risk_score = min(100, risk_score + severity // 4)
        
        return {
            "analysis_type": "bash",
            "risk_score": min(100, risk_score),
            "findings": findings,
            "file_type": "bash",
            "risk_level": cls._get_risk_level(risk_score)
        }

    @classmethod
    def _analyze_python_file(cls, content: str, file_path: str) -> Dict[str, Any]:
        """Analyze Python script for malicious patterns"""
        findings = []
        risk_score = 0
        content_lower = content.lower()
        
        for pattern, description, severity in cls.PYTHON_MALICIOUS_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                findings.append({
                    "line": line_num,
                    "code": match.group()[:80],
                    "description": description,
                    "severity": severity
                })
                risk_score = min(100, risk_score + severity // 2)
        
        # Check for critical patterns (no division - these bypass score limits)
        for pattern, description, severity in cls.CRITICAL_PATTERNS:
            if re.search(pattern, content_lower, re.IGNORECASE):
                findings.append({"description": description, "severity": severity})
                risk_score = max(risk_score, severity)
        
        # Check for suspicious operations
        for pattern, description, severity in cls.SUSPICIOUS_OPERATIONS:
            if re.search(pattern, content, re.IGNORECASE):
                findings.append({
                    "description": description,
                    "severity": severity
                })
                risk_score = min(100, risk_score + severity // 3)
        
        # Check for ransomware code patterns
        for pattern, description, severity in cls.RANSOMWARE_CODE_PATTERNS:
            if re.search(pattern, content_lower, re.IGNORECASE):
                findings.append({
                    "description": description,
                    "severity": severity
                })
                risk_score = min(100, risk_score + severity // 2)
        
        return {
            "analysis_type": "python",
            "risk_score": min(100, risk_score),
            "findings": findings,
            "file_type": "python",
            "risk_level": cls._get_risk_level(risk_score)
        }
    
    @classmethod
    def _analyze_generic_text(cls, content: str, file_path: str) -> Dict[str, Any]:
        """
        Analyze a generic text file for suspicious content.

        Design philosophy:
          - Common English words like 'delete', 'format', 'cmd.exe', 'powershell'
            appear constantly in legitimate documents, READMEs, scripts references,
            etc.  They must NOT generate positive findings on their own.
          - Only signal clearly ransomware-specific language that would be extremely
            unusual in benign text (payment demands, crypto wallet addresses, ransom
            notes, explicit encryption references paired with threat language).
          - Require multiple correlated signals before adding meaningful score so that
            a single word cannot push a clean file past the blocking threshold.
        """
        findings = []
        risk_score = 0
        content_lower = content.lower()

        # --- High-confidence single-term signals (only genuinely alarming words) ---
        # 'ransom' is rarely in legitimate docs and is very specific
        if 'ransom' in content_lower:
            findings.append({
                "description": "File contains ransomware-related language ('ransom')",
                "severity": 50
            })
            risk_score = min(100, risk_score + 25)

        # --- Multi-signal combinations (two signals together are far more reliable) ---
        # Encryption mention + payment demand language → very suspicious in plain text
        has_encrypt = 'encrypt' in content_lower or 'decrypt' in content_lower
        has_payment = 'bitcoin' in content_lower or 'monero' in content_lower or 'wallet' in content_lower
        has_threat = 'pay' in content_lower or 'deadline' in content_lower or 'hours' in content_lower

        if has_encrypt and has_payment:
            findings.append({
                "description": "File references encryption AND cryptocurrency payment — possible ransom note",
                "severity": 80
            })
            risk_score = min(100, risk_score + 40)
        elif has_encrypt and has_threat:
            findings.append({
                "description": "File references encryption AND payment deadline — possible ransom note",
                "severity": 70
            })
            risk_score = min(100, risk_score + 35)
        elif has_payment and has_threat:
            findings.append({
                "description": "File references cryptocurrency payment AND deadline — suspicious content",
                "severity": 60
            })
            risk_score = min(100, risk_score + 30)

        # Explicit ransom note patterns (common structured phrasing in ransom notes)
        ransom_patterns = [
            (r'your files (have been|are) encrypted', 'Classic ransom note opening', 90),
            (r'send .{0,30}bitcoin', 'Bitcoin payment instruction', 80),
            (r'to (recover|restore|decrypt) your files', 'File recovery demand', 75),
            (r'contact .{0,40}tor', 'Tor/dark web contact instruction', 70),
            (r'unique (decrypt|decryption) key', 'Unique decryption key claim', 85),
        ]
        for pattern, description, severity in ransom_patterns:
            if re.search(pattern, content_lower):
                findings.append({"description": description, "severity": severity})
                risk_score = min(100, risk_score + severity)

        # Check for critical patterns (no division - these bypass score limits)
        for pattern, description, severity in cls.CRITICAL_PATTERNS:
            if re.search(pattern, content_lower, re.IGNORECASE):
                findings.append({"description": description, "severity": severity})
                risk_score = max(risk_score, severity)

        # Check for ransomware code patterns in source files
        for pattern, description, severity in cls.RANSOMWARE_CODE_PATTERNS:
            if re.search(pattern, content_lower, re.IGNORECASE):
                findings.append({"description": description, "severity": severity})
                risk_score = min(100, risk_score + severity // 2)

        return {
            "analysis_type": "text",
            "risk_score": min(100, risk_score),
            "findings": findings,
            "file_type": "text",
            "risk_level": cls._get_risk_level(risk_score)
        }
    
    @classmethod
    def _get_risk_level(cls, score: int) -> str:
        """Convert numeric score to risk level"""
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score >= 20:
            return "LOW"
        else:
            return "CLEARED"
    
    @classmethod
    def get_combined_risk_score(cls, entropy: float, ml_prediction: int, content_analysis: Dict) -> Tuple[int, str]:
        """
        Combine entropy, ML prediction, and content analysis into a unified risk score.
        Returns (risk_score, risk_level)
        """
        scores = []
        
        # Entropy score (0-100)
        # High entropy (>7.0) indicates possible encryption/compression
        if entropy >= 7.5:
            entropy_score = 80
        elif entropy >= 7.0:
            entropy_score = 60
        elif entropy >= 6.5:
            entropy_score = 40
        elif entropy >= 5.0:
            entropy_score = 20
        else:
            entropy_score = 10
        scores.append(entropy_score)
        
        # ML prediction score (0-100)
        # Assuming 1 = benign, 0 = ransomware from model
        ml_score = 90 if ml_prediction == 0 else 20
        scores.append(ml_score)
        
        # Content analysis score
        if content_analysis.get("risk_score") is not None:
            content_score = content_analysis["risk_score"]
            scores.append(content_score)
        
        # Weighted average (content analysis is most important)
        if len(scores) == 3:
            combined = (scores[0] * 0.2 + scores[1] * 0.3 + scores[2] * 0.5)
        else:
            combined = sum(scores) / len(scores)
        
        combined = int(min(100, combined))
        risk_level = cls._get_risk_level(combined)
        
        return combined, risk_level

