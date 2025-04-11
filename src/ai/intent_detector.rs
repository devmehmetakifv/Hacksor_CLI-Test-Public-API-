use std::collections::HashMap;
use regex::Regex;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum UserIntent {
    // Security testing intents
    Reconnaissance(ReconTarget),
    VulnerabilityScan(ScanTarget),
    XssTesting(XssTarget),
    PortScan(PortScanTarget),
    DirectoryEnum(DirectoryTarget),
    SubdomainEnum(SubdomainTarget),
    
    // General conversation intents
    Information,
    Help,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReconTarget {
    pub domain: String,
    pub techniques: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanTarget {
    pub domain: String,
    pub scan_type: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct XssTarget {
    pub domain: String,
    pub preferred_tool: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PortScanTarget {
    pub domain: String,
    pub scan_type: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DirectoryTarget {
    pub domain: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SubdomainTarget {
    pub domain: String,
}

/// A system to detect security testing intents in user messages
/// and convert them to structured security commands
#[derive(Clone)]
pub struct IntentDetector {
    // Patterns for detecting specific security testing intents
    recon_patterns: Vec<Regex>,
    vuln_scan_patterns: Vec<Regex>,
    xss_patterns: Vec<Regex>,
    port_scan_patterns: Vec<Regex>,
    dir_enum_patterns: Vec<Regex>,
    subdomain_patterns: Vec<Regex>,
}

impl IntentDetector {
    pub fn new() -> Self {
        Self {
            recon_patterns: vec![
                Regex::new(r"(?i)recon(?:naissance)?").unwrap(),
                Regex::new(r"(?i)gather\s+information").unwrap(),
                Regex::new(r"(?i)discover\s+information").unwrap(),
            ],
            vuln_scan_patterns: vec![
                Regex::new(r"(?i)vuln(?:erability)?\s+scan").unwrap(),
                Regex::new(r"(?i)security\s+scan").unwrap(),
                Regex::new(r"(?i)check\s+(?:for\s+)?vuln(?:erabilit(?:y|ies))?").unwrap(),
            ],
            xss_patterns: vec![
                Regex::new(r"(?i)xss").unwrap(),
                Regex::new(r"(?i)cross[\s-]site\s+scripting").unwrap(),
                Regex::new(r"(?i)script\s+injection").unwrap(),
            ],
            port_scan_patterns: vec![
                Regex::new(r"(?i)port\s+scan").unwrap(),
                Regex::new(r"(?i)scan\s+(?:for\s+)?(?:open\s+)?ports").unwrap(),
                Regex::new(r"(?i)discover\s+(?:open\s+)?ports").unwrap(),
            ],
            dir_enum_patterns: vec![
                Regex::new(r"(?i)dir(?:ectory)?\s+(?:enum(?:eration)?|scan)").unwrap(),
                Regex::new(r"(?i)path\s+discovery").unwrap(),
                Regex::new(r"(?i)find\s+(?:web\s+)?(?:directories|paths|endpoints)").unwrap(),
            ],
            subdomain_patterns: vec![
                Regex::new(r"(?i)subdomain\s+(?:enum(?:eration)?|discovery)").unwrap(),
                Regex::new(r"(?i)find\s+subdomains").unwrap(),
                Regex::new(r"(?i)discover\s+subdomains").unwrap(),
            ],
        }
    }
    
    // Detect intent from user message
    pub fn detect_intent(&self, message: &str) -> UserIntent {
        let message = message.to_lowercase();
        
        // Extract domain if present
        let domain = extract_domain(&message);
        
        // Check for XSS testing intent
        if self.xss_patterns.iter().any(|pattern| pattern.is_match(&message)) {
            if let Some(domain) = domain {
                let preferred_tool = if message.contains("dalfox") {
                    Some("dalfox".to_string())
                } else if message.contains("xsser") {
                    Some("xsser".to_string())
                } else {
                    None
                };
                
                return UserIntent::XssTesting(XssTarget {
                    domain,
                    preferred_tool,
                });
            }
        }
        
        // Check for port scanning intent
        if self.port_scan_patterns.iter().any(|pattern| pattern.is_match(&message)) {
            if let Some(domain) = domain {
                let scan_type = if message.contains("all ports") || message.contains("full") {
                    "full".to_string()
                } else if message.contains("service") || message.contains("version") {
                    "service".to_string()
                } else {
                    "basic".to_string()
                };
                
                return UserIntent::PortScan(PortScanTarget {
                    domain,
                    scan_type,
                });
            }
        }
        
        // Check for directory enumeration intent
        if self.dir_enum_patterns.iter().any(|pattern| pattern.is_match(&message)) {
            if let Some(domain) = domain {
                return UserIntent::DirectoryEnum(DirectoryTarget { domain });
            }
        }
        
        // Check for subdomain enumeration intent
        if self.subdomain_patterns.iter().any(|pattern| pattern.is_match(&message)) {
            if let Some(domain) = domain {
                return UserIntent::SubdomainEnum(SubdomainTarget { domain });
            }
        }
        
        // Check for general vulnerability scanning intent
        if self.vuln_scan_patterns.iter().any(|pattern| pattern.is_match(&message)) {
            if let Some(domain) = domain {
                let scan_type = if message.contains("web") || message.contains("http") {
                    "web".to_string()
                } else {
                    "general".to_string()
                };
                
                return UserIntent::VulnerabilityScan(ScanTarget {
                    domain,
                    scan_type,
                });
            }
        }
        
        // Check for reconnaissance intent
        if self.recon_patterns.iter().any(|pattern| pattern.is_match(&message)) {
            if let Some(domain) = domain {
                let mut techniques = Vec::new();
                
                if message.contains("port") {
                    techniques.push("port_scan".to_string());
                }
                if message.contains("subdomain") {
                    techniques.push("subdomain_enum".to_string());
                }
                if message.contains("directory") || message.contains("path") {
                    techniques.push("directory_enum".to_string());
                }
                
                // If no specific techniques mentioned, include standard recon
                if techniques.is_empty() {
                    techniques.push("basic".to_string());
                }
                
                return UserIntent::Reconnaissance(ReconTarget {
                    domain,
                    techniques,
                });
            }
        }
        
        // Default to unknown intent
        UserIntent::Unknown
    }
    
    // Map user intent to security command
    pub fn map_intent_to_command(&self, intent: &UserIntent) -> Option<(String, HashMap<String, String>)> {
        match intent {
            UserIntent::XssTesting(target) => {
                let mut params = HashMap::new();
                params.insert("target".to_string(), target.domain.clone());
                
                let command_name = match &target.preferred_tool {
                    Some(tool) if tool == "dalfox" => "dalfox",
                    Some(tool) if tool == "xsser" => "xsser",
                    _ => "xsser", // Default to xsser if no preference
                };
                
                Some((command_name.to_string(), params))
            },
            
            UserIntent::PortScan(target) => {
                let mut params = HashMap::new();
                params.insert("target".to_string(), target.domain.clone());
                
                let command_name = match target.scan_type.as_str() {
                    "full" => "nmap_all_ports",
                    "service" => "nmap_service",
                    _ => "nmap_basic",
                };
                
                Some((command_name.to_string(), params))
            },
            
            UserIntent::DirectoryEnum(target) => {
                let mut params = HashMap::new();
                params.insert("target".to_string(), target.domain.clone());
                
                Some(("dirsearch".to_string(), params))
            },
            
            UserIntent::SubdomainEnum(target) => {
                let mut params = HashMap::new();
                params.insert("target".to_string(), target.domain.clone());
                
                Some(("sublist3r".to_string(), params))
            },
            
            UserIntent::VulnerabilityScan(target) => {
                let mut params = HashMap::new();
                params.insert("target".to_string(), target.domain.clone());
                
                let command_name = match target.scan_type.as_str() {
                    "web" => "nikto",
                    _ => "nikto", // Default to nikto for now
                };
                
                Some((command_name.to_string(), params))
            },
            
            UserIntent::Reconnaissance(target) => {
                // For reconnaissance, we'll default to a basic nmap scan
                let mut params = HashMap::new();
                params.insert("target".to_string(), target.domain.clone());
                
                Some(("nmap_basic".to_string(), params))
            },
            
            _ => None,
        }
    }
}

// Helper function to extract domain from message
fn extract_domain(message: &str) -> Option<String> {
    // Try to find common domain patterns
    let domain_regex = Regex::new(r"(?:https?://)?(?:www\.)?([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z0-9]+(?:\.[a-zA-Z0-9]+)*)").ok()?;
    
    if let Some(captures) = domain_regex.captures(message) {
        if let Some(domain_match) = captures.get(1) {
            return Some(domain_match.as_str().to_string());
        }
    }
    
    None
} 