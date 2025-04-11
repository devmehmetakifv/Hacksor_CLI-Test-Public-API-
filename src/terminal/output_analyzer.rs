use std::collections::HashMap;
use std::sync::Arc;
use regex::Regex;
use anyhow::Result;
use tokio::sync::mpsc;
use super::command_monitor::{CommandOutput, FindingSeverity, CommandMonitor, create_finding, CommandType};
use std::time::{Duration, Instant};

/// Analyzes command output to detect security findings and patterns
pub struct OutputAnalyzer {
    monitor: Arc<CommandMonitor>,
    output_rx: mpsc::Receiver<CommandOutput>,
    buffer: HashMap<String, Vec<String>>,
    port_scan_patterns: Vec<Regex>,
    vulnerability_patterns: Vec<Regex>,
    path_discovery_patterns: Vec<Regex>,
    subdomain_patterns: Vec<Regex>,
    last_analyzed: HashMap<String, Instant>,
    running: bool,
}

impl OutputAnalyzer {
    pub fn new(monitor: Arc<CommandMonitor>, output_rx: mpsc::Receiver<CommandOutput>) -> Self {
        // Compile regex patterns for different types of findings
        let port_scan_patterns = vec![
            // Nmap open port patterns
            Regex::new(r"(\d+)/(?:tcp|udp)\s+open\s+(\S+)").unwrap(),
            Regex::new(r"PORT\s+STATE\s+SERVICE(?:\s+VERSION)?").unwrap(),
        ];
        
        let vulnerability_patterns = vec![
            // General vulnerability patterns
            Regex::new(r"(?i)vulnerable|vulnerability|exploit|deprecated").unwrap(),
            // Version disclosure patterns
            Regex::new(r"(?i)(apache|nginx|iis|tomcat|php|mysql|postgresql|mssql)(?:/| |-)(\d+\.\d+\.?\d*)").unwrap(),
            // CVE patterns
            Regex::new(r"(?i)CVE-\d{4}-\d{4,7}").unwrap(),
            // XSS patterns
            Regex::new(r"(?i)xss|cross-site").unwrap(),
            // SQL injection patterns
            Regex::new(r"(?i)sql(?:\s+)?injection").unwrap(),
        ];
        
        let path_discovery_patterns = vec![
            // Directory/file patterns
            Regex::new(r"(?i)Status: 200\s+Size:\s+\d+\s+Path:\s+(\S+)").unwrap(),
            Regex::new(r"(?i)\(Status: 200\)\s+\[Size: \d+\]").unwrap(),
            // Admin/config paths
            Regex::new(r"(?i)/(?:admin|config|setup|install|backup|wp-admin|phpMyAdmin)(?:/|\s|$)").unwrap(),
        ];
        
        let subdomain_patterns = vec![
            // Subdomain patterns
            Regex::new(r"(?i)found\s+(\d+)\s+subdomains").unwrap(),
            Regex::new(r"(?i)(\S+\.[\w-]+\.\w+)").unwrap(),
        ];
        
        Self {
            monitor,
            output_rx,
            buffer: HashMap::new(),
            port_scan_patterns,
            vulnerability_patterns,
            path_discovery_patterns,
            subdomain_patterns,
            last_analyzed: HashMap::new(),
            running: false,
        }
    }
    
    /// Start analyzing command output
    pub async fn start(&mut self) -> Result<()> {
        if self.running {
            return Ok(());
        }
        
        self.running = true;
        
        // Main analysis loop
        while let Some(output) = self.output_rx.recv().await {
            // Add output to buffer
            let buffer = self.buffer.entry(output.command_id.clone()).or_insert_with(Vec::new);
            buffer.push(output.line.clone());
            
            // Check if it's time to analyze this command's output
            let should_analyze = if let Some(last_analyzed) = self.last_analyzed.get(&output.command_id) {
                last_analyzed.elapsed() > Duration::from_secs(5) // Only analyze every 5 seconds
            } else {
                true
            };
            
            if should_analyze {
                self.analyze_command_output(&output.command_id).await?;
                self.last_analyzed.insert(output.command_id.clone(), Instant::now());
            }
        }
        
        self.running = false;
        Ok(())
    }
    
    /// Analyze output of a specific command
    async fn analyze_command_output(&self, command_id: &str) -> Result<()> {
        // Get command information
        let command = match self.monitor.get_command(command_id) {
            Some(cmd) => cmd,
            None => return Ok(()),
        };
        
        // Get output buffer
        let buffer = match self.buffer.get(command_id) {
            Some(buffer) => buffer,
            None => return Ok(()),
        };
        
        // Skip if buffer is empty
        if buffer.is_empty() {
            return Ok(());
        }
        
        // Create analysis context with recent output
        let context = buffer.join("\n");
        
        // Different analysis based on command type
        match command.command_type {
            CommandType::Reconnaissance => {
                // Look for open ports in port scanning output
                self.analyze_port_scan(&context, command_id).await?;
                
                // Look for subdomains
                self.analyze_subdomains(&context, command_id).await?;
            },
            CommandType::Scanning => {
                // Look for vulnerabilities
                self.analyze_vulnerabilities(&context, command_id).await?;
            },
            CommandType::Vulnerability => {
                // Look for discovered vulnerabilities
                self.analyze_vulnerabilities(&context, command_id).await?;
            },
            _ => {
                // Generic analysis
                self.analyze_generic_output(&context, command_id).await?;
            }
        }
        
        Ok(())
    }
    
    /// Analyze port scanning output (nmap, etc.)
    async fn analyze_port_scan(&self, context: &str, command_id: &str) -> Result<()> {
        // Look for open ports
        let mut open_ports = Vec::new();
        
        for line in context.lines() {
            for pattern in &self.port_scan_patterns {
                if let Some(captures) = pattern.captures(line) {
                    if captures.len() > 1 {
                        if let Some(port) = captures.get(1) {
                            let service = if captures.len() > 2 {
                                captures.get(2).map_or("", |m| m.as_str())
                            } else {
                                ""
                            };
                            
                            open_ports.push((port.as_str().to_string(), service.to_string()));
                        }
                    }
                }
            }
        }
        
        // If we have open ports, generate a finding
        if !open_ports.is_empty() {
            // Create port list for description
            let port_list = open_ports.iter()
                .map(|(port, service)| {
                    if service.is_empty() {
                        format!("Port {}", port)
                    } else {
                        format!("Port {} ({})", port, service)
                    }
                })
                .collect::<Vec<_>>()
                .join(", ");
            
            // Create the finding
            let finding = create_finding(
                &format!("Open Ports Detected"),
                &format!("The following ports were found open: {}", port_list),
                FindingSeverity::Info,
                command_id,
                context,
            );
            
            self.monitor.add_finding(finding).await?;
            
            // Update command summary
            self.monitor.update_command_summary(
                command_id,
                &format!("Detected {} open ports: {}", open_ports.len(), port_list),
            )?;
        }
        
        Ok(())
    }
    
    /// Analyze vulnerability scanning output
    async fn analyze_vulnerabilities(&self, context: &str, command_id: &str) -> Result<()> {
        // Look for vulnerability indicators
        let mut findings = Vec::new();
        
        // Look for software versions
        for line in context.lines() {
            for pattern in &self.vulnerability_patterns {
                if let Some(captures) = pattern.captures(line) {
                    // Check for software versions
                    if captures.len() > 2 {
                        let software = captures.get(1).map_or("", |m| m.as_str());
                        let version = captures.get(2).map_or("", |m| m.as_str());
                        
                        if !software.is_empty() && !version.is_empty() {
                            findings.push((
                                format!("{} Version Disclosure", software),
                                format!("Detected {} version {}", software, version),
                                FindingSeverity::Low,
                                line.to_string(),
                            ));
                        }
                    } 
                    // Check for CVEs
                    else if line.contains("CVE-") {
                        // Extract CVE ID
                        let cve_pattern = Regex::new(r"CVE-\d{4}-\d{4,7}").unwrap();
                        if let Some(cve) = cve_pattern.find(line) {
                            findings.push((
                                format!("Potential CVE Detected"),
                                format!("Found reference to {} in output", cve.as_str()),
                                FindingSeverity::High,
                                line.to_string(),
                            ));
                        }
                    }
                    // Check for vulnerability keywords
                    else if line.to_lowercase().contains("vulnerable") || 
                             line.to_lowercase().contains("vulnerability") ||
                             line.to_lowercase().contains("exploit") {
                        findings.push((
                            format!("Potential Vulnerability Detected"),
                            format!("Detected potential vulnerability indicator in output"),
                            FindingSeverity::Medium,
                            line.to_string(),
                        ));
                    }
                    // Check for XSS
                    else if line.to_lowercase().contains("xss") || 
                             line.to_lowercase().contains("cross-site scripting") {
                        findings.push((
                            format!("Potential XSS Vulnerability"),
                            format!("Detected potential XSS vulnerability indicator"),
                            FindingSeverity::High,
                            line.to_string(),
                        ));
                    }
                    // Check for SQL injection
                    else if line.to_lowercase().contains("sql injection") {
                        findings.push((
                            format!("Potential SQL Injection Vulnerability"),
                            format!("Detected potential SQL injection vulnerability indicator"),
                            FindingSeverity::High,
                            line.to_string(),
                        ));
                    }
                }
            }
        }
        
        // Add all findings
        for (title, description, severity, raw_output) in findings {
            let finding = create_finding(
                &title,
                &description,
                severity,
                command_id,
                &raw_output,
            );
            
            self.monitor.add_finding(finding).await?;
        }
        
        Ok(())
    }
    
    /// Analyze subdomain discovery output
    async fn analyze_subdomains(&self, context: &str, command_id: &str) -> Result<()> {
        // Extract subdomains
        let mut subdomains = Vec::new();
        
        for line in context.lines() {
            for pattern in &self.subdomain_patterns {
                if let Some(captures) = pattern.captures(line) {
                    if captures.len() > 1 {
                        if let Some(subdomain) = captures.get(1) {
                            let subdomain_str = subdomain.as_str();
                            
                            // Simple validation to filter out non-subdomain matches
                            if subdomain_str.contains('.') && 
                               !subdomain_str.starts_with("www.") &&
                               !subdomain_str.contains("://") {
                                subdomains.push(subdomain_str.to_string());
                            }
                        }
                    }
                }
            }
        }
        
        // Filter out duplicates
        subdomains.sort();
        subdomains.dedup();
        
        // If we have subdomains, generate a finding
        if !subdomains.is_empty() {
            // Create subdomain list for description
            let subdomain_list = subdomains.iter()
                .take(10) // Limit to 10 for the description
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            
            let additional = if subdomains.len() > 10 {
                format!(" and {} more", subdomains.len() - 10)
            } else {
                String::new()
            };
            
            // Create the finding
            let finding = create_finding(
                &format!("Subdomains Discovered"),
                &format!("Discovered {} subdomains: {}{}", subdomains.len(), subdomain_list, additional),
                FindingSeverity::Info,
                command_id,
                &subdomains.join("\n"),
            );
            
            self.monitor.add_finding(finding).await?;
            
            // Update command summary
            self.monitor.update_command_summary(
                command_id,
                &format!("Discovered {} subdomains", subdomains.len()),
            )?;
        }
        
        Ok(())
    }
    
    /// Analyze directory/path discovery output
    async fn analyze_paths(&self, context: &str, command_id: &str) -> Result<()> {
        // Extract interesting paths
        let mut paths = Vec::new();
        let mut admin_paths = Vec::new();
        
        for line in context.lines() {
            for pattern in &self.path_discovery_patterns {
                if let Some(captures) = pattern.captures(line) {
                    // Handle admin/sensitive paths
                    if line.contains("/admin") || 
                       line.contains("/config") || 
                       line.contains("/setup") || 
                       line.contains("/install") || 
                       line.contains("/backup") || 
                       line.contains("/wp-admin") || 
                       line.contains("/phpMyAdmin") {
                        admin_paths.push(line.to_string());
                    }
                    // Handle regular paths
                    else if captures.len() > 1 {
                        if let Some(path) = captures.get(1) {
                            paths.push(path.as_str().to_string());
                        }
                    }
                }
            }
        }
        
        // Add findings for interesting paths
        if !paths.is_empty() {
            // Create path list
            let path_list = paths.iter()
                .take(10)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            
            let additional = if paths.len() > 10 {
                format!(" and {} more", paths.len() - 10)
            } else {
                String::new()
            };
            
            // Create the finding
            let finding = create_finding(
                &format!("Interesting Paths Discovered"),
                &format!("Discovered {} interesting paths: {}{}", paths.len(), path_list, additional),
                FindingSeverity::Info,
                command_id,
                &paths.join("\n"),
            );
            
            self.monitor.add_finding(finding).await?;
        }
        
        // Add findings for admin/sensitive paths
        if !admin_paths.is_empty() {
            // Create path list
            let admin_list = admin_paths.iter()
                .take(5)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            
            let additional = if admin_paths.len() > 5 {
                format!(" and {} more", admin_paths.len() - 5)
            } else {
                String::new()
            };
            
            // Create the finding
            let finding = create_finding(
                &format!("Potentially Sensitive Paths Discovered"),
                &format!("Discovered {} potentially sensitive paths: {}{}", 
                         admin_paths.len(), admin_list, additional),
                FindingSeverity::Medium,
                command_id,
                &admin_paths.join("\n"),
            );
            
            self.monitor.add_finding(finding).await?;
        }
        
        // Update command summary
        if !paths.is_empty() || !admin_paths.is_empty() {
            let path_count = paths.len();
            let admin_count = admin_paths.len();
            
            self.monitor.update_command_summary(
                command_id,
                &format!("Discovered {} paths ({} potentially sensitive)", 
                         path_count + admin_count, admin_count),
            )?;
        }
        
        Ok(())
    }
    
    /// Analyze generic command output for any potential findings
    async fn analyze_generic_output(&self, context: &str, command_id: &str) -> Result<()> {
        // Try all analyzers
        self.analyze_port_scan(context, command_id).await?;
        self.analyze_vulnerabilities(context, command_id).await?;
        self.analyze_subdomains(context, command_id).await?;
        self.analyze_paths(context, command_id).await?;
        
        Ok(())
    }
} 