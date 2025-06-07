import re
import json
from typing import Dict, Any, List, Tuple
from urllib.parse import unquote
import logging

class ThreatPatternClassifier:
    """Pattern-based threat classification system for log anomalies."""
    
    def __init__(self):
        self.threat_patterns = self._initialize_patterns()
        self.severity_mapping = {
            "SQL Injection": "High",
            "XSS Attack": "High", 
            "Command Injection": "Critical",
            "Path Traversal": "High",
            "Brute Force": "Medium",
            "DDoS": "High",
            "Malware": "Critical",
            "Data Exfiltration": "Critical",
            "Privilege Escalation": "High",
            "Authentication Bypass": "High",
            "CSRF": "Medium",
            "XXE": "High",
            "LDAP Injection": "High",
            "File Upload Attack": "Medium",
            "Suspicious Activity": "Low",
            "Unknown Anomaly": "Low"
        }
    
    def _initialize_patterns(self) -> Dict[str, List[Dict]]:
        """Initialize threat detection patterns."""
        return {
            "SQL Injection": [
                {
                    "patterns": [
                        r"(?i)(union\s+select|union\s+all\s+select)",
                        r"(?i)(drop\s+table|drop\s+database)",
                        r"(?i)(insert\s+into.*values|update.*set.*where)",
                        r"(?i)(delete\s+from\s+\w+)",
                        r"(?i)(or\s+1\s*=\s*1|or\s+'1'\s*=\s*'1')",
                        r"(?i)(and\s+1\s*=\s*1|and\s+'1'\s*=\s*'1')",
                        r"(?i)('.*or.*'.*=.*'|\".*or.*\".*=.*\")",
                        r"(?i)(admin'--|admin\"--)",
                        r"(?i)(exec\s*\(|execute\s*\()",
                        r"(?i)(information_schema|sysobjects|syscolumns)",
                        r"(?i)(waitfor\s+delay|benchmark\s*\()",
                        r"(?i)(\bxp_cmdshell\b|\bsp_executesql\b)"
                    ],
                    "weight": 1.0
                }
            ],
            
            "XSS Attack": [
                {
                    "patterns": [
                        r"(?i)(<script[^>]*>.*</script>|<script[^>]*>)",
                        r"(?i)(javascript\s*:|vbscript\s*:)",
                        r"(?i)(on\w+\s*=\s*[\"'].*[\"'])",  # onerror, onload, etc.
                        r"(?i)(alert\s*\(|confirm\s*\(|prompt\s*\()",
                        r"(?i)(document\.(cookie|domain|location))",
                        r"(?i)(<iframe[^>]*>|<embed[^>]*>|<object[^>]*>)",
                        r"(?i)(eval\s*\(|settimeout\s*\(|setinterval\s*\()",
                        r"(?i)(<img[^>]*onerror|<svg[^>]*onload)",
                        r"(?i)(fromcharcode|string\.fromcharcode)",
                        r"(?i)(%3Cscript|%3C%2Fscript|&lt;script)"
                    ],
                    "weight": 1.0
                }
            ],
            
            "Command Injection": [
                {
                    "patterns": [
                        r"(?i)(\|\s*\w+|\&\&\s*\w+|\;\s*\w+)",
                        r"(?i)(\$\(.*\)|\`.*\`)",
                        r"(?i)(wget\s+|curl\s+|nc\s+|netcat\s+)",
                        r"(?i)(cat\s+/etc/passwd|cat\s+/etc/shadow)",
                        r"(?i)(rm\s+-rf|del\s+/f|format\s+c:)",
                        r"(?i)(whoami|id\s*$|uname\s+-a)",
                        r"(?i)(powershell|cmd\.exe|/bin/sh|/bin/bash)",
                        r"(?i)(system\s*\(|exec\s*\(|shell_exec\s*\()",
                        r"(?i)(%0a|%0d|%00|\n|\r)"
                    ],
                    "weight": 1.0
                }
            ],
            
            "Path Traversal": [
                {
                    "patterns": [
                        r"(?i)(\.\.\/|\.\.\\)",
                        r"(?i)(%2e%2e%2f|%2e%2e%5c)",
                        r"(?i)(\/etc\/passwd|\/etc\/shadow|\/windows\/system32)",
                        r"(?i)(\.\.%2f|\.\.%5c)",
                        r"(?i)(file\:\/\/|file\:\\\\)",
                        r"(?i)(boot\.ini|win\.ini|autoexec\.bat)"
                    ],
                    "weight": 1.0
                }
            ],
            
            "Brute Force": [
                {
                    "patterns": [
                        r"(?i)(failed\s+login|login\s+failed|authentication\s+failed)",
                        r"(?i)(invalid\s+password|incorrect\s+password|wrong\s+password)",
                        r"(?i)(too\s+many\s+attempts|account\s+locked|rate\s+limit)",
                        r"(?i)(unauthorized\s+access|access\s+denied)",
                        r"(?i)(multiple\s+failed|repeated\s+login)",
                        r"(?i)(password\s+spray|credential\s+stuffing)"
                    ],
                    "weight": 0.8,
                    "frequency_threshold": 5  # Multiple occurrences increase confidence
                }
            ],
            
            "DDoS": [
                {
                    "patterns": [
                        r"(?i)(too\s+many\s+connections|connection\s+limit)",
                        r"(?i)(rate\s+limit\s+exceeded|bandwidth\s+exceeded)",
                        r"(?i)(flood|flooding|amplification)",
                        r"(?i)(syn\s+flood|udp\s+flood|icmp\s+flood)",
                        r"(?i)(high\s+traffic|traffic\s+spike)",
                        r"(?i)(service\s+unavailable|server\s+overload)"
                    ],
                    "weight": 0.9
                }
            ],
            
            "Malware": [
                {
                    "patterns": [
                        r"(?i)(malware|virus|trojan|backdoor|rootkit)",
                        r"(?i)(suspicious\s+file|infected\s+file)",
                        r"(?i)(payload|shellcode|exploit)",
                        r"(?i)(ransomware|cryptolocker|wannacry)",
                        r"(?i)(botnet|c2|command\s+control)",
                        r"(?i)(keylogger|spyware|adware)"
                    ],
                    "weight": 1.0
                }
            ],
            
            "Data Exfiltration": [
                {
                    "patterns": [
                        r"(?i)(data\s+export|bulk\s+download|mass\s+download)",
                        r"(?i)(unusual\s+data\s+transfer|large\s+file\s+transfer)",
                        r"(?i)(database\s+dump|sql\s+dump|backup\s+download)",
                        r"(?i)(sensitive\s+data|confidential|classified)",
                        r"(?i)(ftp\s+upload|scp\s+transfer|rsync)"
                    ],
                    "weight": 0.9
                }
            ],
            
            "Authentication Bypass": [
                {
                    "patterns": [
                        r"(?i)(bypass\s+auth|skip\s+authentication)",
                        r"(?i)(session\s+hijack|session\s+fixation)",
                        r"(?i)(token\s+manipulation|jwt\s+manipulation)",
                        r"(?i)(privilege\s+escalation|elevation\s+of\s+privilege)",
                        r"(?i)(unauthorized\s+admin|admin\s+bypass)"
                    ],
                    "weight": 1.0
                }
            ]
        }
    
    def classify_threat(self, log_message: str, anomaly_score: float, source_ip: str = None, 
                       source_type: str = None) -> Dict[str, Any]:
        """
        Classify the threat type based on log message patterns.
        
        Args:
            log_message: The log message to analyze
            anomaly_score: The anomaly score from the ML model
            source_ip: Source IP address (optional)
            source_type: Type of log source (optional)
            
        Returns:
            Dict containing threat classification results
        """
        # URL decode the message to catch encoded attacks
        decoded_message = unquote(log_message)
        
        threat_scores = {}
        matched_patterns = {}
        
        # Check each threat category
        for threat_type, pattern_groups in self.threat_patterns.items():
            max_score = 0
            patterns_matched = []
            
            for pattern_group in pattern_groups:
                patterns = pattern_group["patterns"]
                weight = pattern_group.get("weight", 1.0)
                
                matches = 0
                for pattern in patterns:
                    if re.search(pattern, log_message) or re.search(pattern, decoded_message):
                        matches += 1
                        patterns_matched.append(pattern)
                
                if matches > 0:
                    # Calculate score based on number of matches and weight
                    score = (matches / len(patterns)) * weight
                    
                    # Apply frequency threshold if specified
                    if "frequency_threshold" in pattern_group:
                        if matches >= pattern_group["frequency_threshold"]:
                            score *= 1.5  # Boost score for frequent patterns
                    
                    max_score = max(max_score, score)
            
            if max_score > 0:
                threat_scores[threat_type] = max_score
                matched_patterns[threat_type] = patterns_matched
        
        # Determine the most likely threat
        if threat_scores:
            primary_threat = max(threat_scores, key=threat_scores.get)
            confidence = threat_scores[primary_threat]
            
            # Adjust confidence based on anomaly score
            final_confidence = min(confidence * anomaly_score, 1.0)
            
            return {
                "threat_type": primary_threat,
                "confidence": final_confidence,
                "severity": self.severity_mapping.get(primary_threat, "Low"),
                "all_threats": threat_scores,
                "matched_patterns": matched_patterns.get(primary_threat, []),
                "details": self._generate_threat_details(primary_threat, log_message)
            }
        else:
            # No specific patterns matched, classify based on anomaly score
            if anomaly_score > 0.8:
                threat_type = "Unknown Anomaly"
                severity = "Medium"
            else:
                threat_type = "Suspicious Activity"
                severity = "Low"
            
            return {
                "threat_type": threat_type,
                "confidence": anomaly_score,
                "severity": severity,
                "all_threats": {},
                "matched_patterns": [],
                "details": f"Anomalous activity detected with score {anomaly_score:.2f}"
            }
    
    def _generate_threat_details(self, threat_type: str, log_message: str) -> str:
        """Generate detailed description of the threat."""
        details = {
            "SQL Injection": "Potential SQL injection attack detected. Malicious SQL code may be attempting to manipulate database queries.",
            "XSS Attack": "Cross-Site Scripting attack detected. Malicious script injection attempt identified.",
            "Command Injection": "Command injection attack detected. Attempt to execute system commands through application input.",
            "Path Traversal": "Directory traversal attack detected. Attempt to access files outside intended directory.",
            "Brute Force": "Brute force attack detected. Multiple failed authentication attempts identified.",
            "DDoS": "Distributed Denial of Service attack detected. High volume of requests may be attempting to overwhelm the system.",
            "Malware": "Malware-related activity detected. Suspicious file or payload identified.",
            "Data Exfiltration": "Potential data exfiltration detected. Unusual data transfer patterns identified.",
            "Authentication Bypass": "Authentication bypass attempt detected. Unauthorized access attempt identified."
        }
        
        return details.get(threat_type, f"Suspicious activity classified as {threat_type}")
    
    def add_custom_pattern(self, threat_type: str, patterns: List[str], weight: float = 1.0):
        """Add custom threat detection patterns."""
        if threat_type not in self.threat_patterns:
            self.threat_patterns[threat_type] = []
        
        self.threat_patterns[threat_type].append({
            "patterns": patterns,
            "weight": weight
        })
        
        if threat_type not in self.severity_mapping:
            self.severity_mapping[threat_type] = "Medium"
