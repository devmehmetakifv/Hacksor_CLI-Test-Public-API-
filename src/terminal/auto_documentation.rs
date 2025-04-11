use std::sync::Arc;
use anyhow::{Result, Context, anyhow};
use tokio::sync::mpsc;
use std::path::PathBuf;
use std::fs::{self, OpenOptions};
use std::io::Write;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use std::collections::HashMap;
use regex::Regex;

use super::command_monitor::{SecurityFinding, FindingSeverity, CommandMonitor};

/// Represents a documented finding in Markdown format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentedFinding {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: FindingSeverity,
    pub discovery_date: DateTime<Utc>,
    pub discovery_command: String,
    pub raw_evidence: String,
    pub follow_up_actions: Vec<FollowUpAction>,
    pub status: FindingStatus,
    pub file_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FindingStatus {
    New,
    InProgress,
    Verified,
    Documented,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FollowUpAction {
    pub id: String,
    pub description: String,
    pub command: Option<String>,
    pub status: ActionStatus,
    pub result: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ActionStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
}

/// Manages automatic documentation of security findings
pub struct AutoDocumentation {
    monitor: Arc<CommandMonitor>,
    finding_rx: mpsc::Receiver<SecurityFinding>,
    documented_findings: HashMap<String, DocumentedFinding>,
    work_dir: PathBuf,
    findings_dir: PathBuf,
    running: bool,
    follow_up_tx: mpsc::Sender<FollowUpAction>,
}

impl AutoDocumentation {
    pub fn new(
        monitor: Arc<CommandMonitor>, 
        finding_rx: mpsc::Receiver<SecurityFinding>,
        follow_up_tx: mpsc::Sender<FollowUpAction>,
        work_dir: PathBuf
    ) -> Result<Self> {
        // Create directory for findings
        let findings_dir = work_dir.join("findings");
        fs::create_dir_all(&findings_dir)?;
        
        Ok(Self {
            monitor,
            finding_rx,
            documented_findings: HashMap::new(),
            work_dir,
            findings_dir,
            running: false,
            follow_up_tx,
        })
    }
    
    /// Start the auto-documentation process
    pub async fn start(&mut self) -> Result<()> {
        if self.running {
            return Ok(());
        }
        
        self.running = true;
        
        // Main documentation loop
        while let Some(finding) = self.finding_rx.recv().await {
            // Generate a documented finding
            let documented = self.document_finding(finding).await?;
            
            // Generate follow-up actions
            let actions = self.generate_follow_up_actions(&documented).await?;
            
            // Queue follow-up actions
            for action in actions {
                if let Err(e) = self.follow_up_tx.send(action).await {
                    eprintln!("Failed to queue follow-up action: {}", e);
                }
            }
        }
        
        self.running = false;
        Ok(())
    }
    
    /// Document a security finding
    async fn document_finding(&mut self, finding: SecurityFinding) -> Result<DocumentedFinding> {
        // Get command information to provide context
        let command = self.monitor.get_command(&finding.command_id)
            .context("Failed to get command information for finding")?;
        
        // Create a unique ID for the documented finding if not already existing
        let doc_id = format!("FINDING-{}", Uuid::new_v4().to_string().split('-').next().unwrap_or("UNKNOWN"));
        
        // Create file path for the finding
        let file_name = format!("{}_{}_{}.md", 
            chrono::Utc::now().format("%Y%m%d"),
            doc_id,
            finding.title.to_lowercase().replace(' ', "_").replace(|c: char| !c.is_alphanumeric() && c != '_', "")
        );
        
        let file_path = self.findings_dir.join(file_name);
        
        // Create the documented finding
        let documented = DocumentedFinding {
            id: doc_id,
            title: finding.title,
            description: finding.description,
            severity: finding.severity,
            discovery_date: finding.timestamp,
            discovery_command: command.command.clone(),
            raw_evidence: finding.raw_output,
            follow_up_actions: Vec::new(),
            status: FindingStatus::New,
            file_path: file_path.clone(),
        };
        
        // Save the finding to disk
        self.save_finding_to_file(&documented)?;
        
        // Store in memory
        self.documented_findings.insert(documented.id.clone(), documented.clone());
        
        Ok(documented)
    }
    
    /// Generate follow-up actions based on the finding
    async fn generate_follow_up_actions(&self, finding: &DocumentedFinding) -> Result<Vec<FollowUpAction>> {
        let mut actions = Vec::new();
        
        // Common follow-up: Document the finding fully
        actions.push(FollowUpAction {
            id: Uuid::new_v4().to_string(),
            description: format!("Update documentation for finding {}", finding.id),
            command: None,
            status: ActionStatus::Pending,
            result: None,
        });
        
        // Different follow-up actions based on finding type
        if finding.title.contains("Open Port") {
            // For open ports, do service version detection
            let port_pattern = Regex::new(r"Port (\d+)").unwrap();
            let mut port_list = Vec::new();
            
            for cap in port_pattern.captures_iter(&finding.description) {
                if let Some(port) = cap.get(1) {
                    port_list.push(port.as_str());
                }
            }
            
            if !port_list.is_empty() {
                let target = extract_target_from_command(&finding.discovery_command);
                
                if let Some(target) = target {
                    // Create targeted port scan for version detection
                    let ports = port_list.join(",");
                    let command = format!("nmap -sV -p{} {}", ports, target);
                    
                    actions.push(FollowUpAction {
                        id: Uuid::new_v4().to_string(),
                        description: format!("Perform service version detection on ports: {}", ports),
                        command: Some(command),
                        status: ActionStatus::Pending,
                        result: None,
                    });
                }
            }
        } else if finding.title.contains("Subdomain") {
            // For subdomains, check for alive hosts
            // Extract subdomains from the finding's raw evidence
            let lines: Vec<&str> = finding.raw_evidence.lines().collect();
            
            if !lines.is_empty() {
                let subdomains_file = self.work_dir.join("subdomains.txt");
                
                // Create file with extracted subdomains
                let mut file = OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(&subdomains_file)?;
                
                for line in lines {
                    writeln!(file, "{}", line)?;
                }
                
                // Create follow-up action to check for alive hosts
                actions.push(FollowUpAction {
                    id: Uuid::new_v4().to_string(),
                    description: "Check which subdomains are active and resolve".to_string(),
                    command: Some(format!("cat {:?} | httpx -silent -o {:?}", 
                        subdomains_file, 
                        self.work_dir.join("alive_subdomains.txt"))),
                    status: ActionStatus::Pending,
                    result: None,
                });
            }
        } else if finding.title.contains("Path") || finding.title.contains("Directory") {
            // For discovered paths, check for vulnerabilities
            // No specific command here as it depends on the type of path/directory
            actions.push(FollowUpAction {
                id: Uuid::new_v4().to_string(),
                description: "Manually analyze discovered paths for security vulnerabilities".to_string(),
                command: None,
                status: ActionStatus::Pending,
                result: None,
            });
        } else if finding.title.contains("Version") {
            // For version disclosures, look for known vulnerabilities
            let version_pattern = Regex::new(r"(\w+) version ([\d\.]+)").unwrap();
            
            if let Some(cap) = version_pattern.captures(&finding.description) {
                if cap.len() > 2 {
                    let software = cap.get(1).map_or("", |m| m.as_str());
                    let version = cap.get(2).map_or("", |m| m.as_str());
                    
                    if !software.is_empty() && !version.is_empty() {
                        // Search for known vulnerabilities
                        actions.push(FollowUpAction {
                            id: Uuid::new_v4().to_string(),
                            description: format!("Search for known vulnerabilities in {} {}", software, version),
                            command: Some(format!("searchsploit {} {}", software, version)),
                            status: ActionStatus::Pending,
                            result: None,
                        });
                    }
                }
            }
        } else if finding.title.contains("CVE") {
            // For CVEs, get more information
            let cve_pattern = Regex::new(r"(CVE-\d{4}-\d{4,7})").unwrap();
            
            if let Some(cap) = cve_pattern.captures(&finding.description) {
                if let Some(cve_id) = cap.get(1) {
                    // Look up CVE details
                    actions.push(FollowUpAction {
                        id: Uuid::new_v4().to_string(),
                        description: format!("Gather detailed information about {}", cve_id.as_str()),
                        command: Some(format!("curl -s https://cve.circl.lu/api/cve/{}", cve_id.as_str())),
                        status: ActionStatus::Pending,
                        result: None,
                    });
                }
            }
        } else if finding.title.contains("XSS") || finding.title.contains("Injection") {
            // For potential XSS/Injection, suggest manual verification
            actions.push(FollowUpAction {
                id: Uuid::new_v4().to_string(),
                description: format!("Manually verify the {} finding", 
                    if finding.title.contains("XSS") { "XSS" } else { "SQL Injection" }),
                command: None,
                status: ActionStatus::Pending,
                result: None,
            });
        }
        
        Ok(actions)
    }
    
    /// Save a documented finding to a Markdown file
    fn save_finding_to_file(&self, finding: &DocumentedFinding) -> Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&finding.file_path)?;
        
        // Write Markdown format
        writeln!(file, "# {} ({})", finding.title, finding.id)?;
        writeln!(file, "")?;
        writeln!(file, "## Description")?;
        writeln!(file, "{}", finding.description)?;
        writeln!(file, "")?;
        writeln!(file, "**Severity:** {:?}", finding.severity)?;
        writeln!(file, "**Discovery Date:** {}", finding.discovery_date.format("%Y-%m-%d %H:%M:%S UTC"))?;
        writeln!(file, "**Status:** {:?}", finding.status)?;
        writeln!(file, "")?;
        writeln!(file, "## Discovery Method")?;
        writeln!(file, "```")?;
        writeln!(file, "{}", finding.discovery_command)?;
        writeln!(file, "```")?;
        writeln!(file, "")?;
        writeln!(file, "## Evidence")?;
        writeln!(file, "```")?;
        writeln!(file, "{}", finding.raw_evidence)?;
        writeln!(file, "```")?;
        writeln!(file, "")?;
        
        // Write follow-up actions if any
        if !finding.follow_up_actions.is_empty() {
            writeln!(file, "## Follow-up Actions")?;
            writeln!(file, "")?;
            
            for (i, action) in finding.follow_up_actions.iter().enumerate() {
                writeln!(file, "### Action {}: {}", i+1, action.description)?;
                writeln!(file, "**Status:** {:?}", action.status)?;
                
                if let Some(cmd) = &action.command {
                    writeln!(file, "**Command:**")?;
                    writeln!(file, "```")?;
                    writeln!(file, "{}", cmd)?;
                    writeln!(file, "```")?;
                }
                
                if let Some(result) = &action.result {
                    writeln!(file, "**Result:**")?;
                    writeln!(file, "```")?;
                    writeln!(file, "{}", result)?;
                    writeln!(file, "```")?;
                }
                
                writeln!(file, "")?;
            }
        }
        
        // Write notes section
        writeln!(file, "## Notes")?;
        writeln!(file, "_Add your notes here_")?;
        
        Ok(())
    }
    
    /// Update a documented finding with follow-up action results
    pub fn update_finding_with_action_result(&mut self, action: &FollowUpAction) -> Result<()> {
        // Find the matching finding and action
        let mut finding_to_save = None;
        
        'outer: for finding in self.documented_findings.values_mut() {
            for follow_up in &mut finding.follow_up_actions {
                if follow_up.id == action.id {
                    // Update the action
                    follow_up.status = action.status.clone();
                    follow_up.result = action.result.clone();
                    
                    // Clone the finding for saving
                    finding_to_save = Some(finding.clone());
                    break 'outer;
                }
            }
        }
        
        // Save the updated finding if found
        if let Some(finding) = finding_to_save {
            self.save_finding_to_file(&finding)?;
            Ok(())
        } else {
            Err(anyhow!("Could not find matching action ID in any finding"))
        }
    }
    
    /// Add a follow-up action to a finding
    pub fn add_follow_up_to_finding(&mut self, finding_id: &str, action: FollowUpAction) -> Result<()> {
        let finding_opt = self.documented_findings.get_mut(finding_id).map(|finding| {
            finding.follow_up_actions.push(action.clone());
            finding.clone()
        });
        
        if let Some(finding) = finding_opt {
            self.save_finding_to_file(&finding)?;
            Ok(())
        } else {
            Err(anyhow!("Finding not found: {}", finding_id))
        }
    }
    
    /// Generate a summary report of all findings
    pub fn generate_summary_report(&self, output_file: &PathBuf) -> Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(output_file)?;
        
        // Collect findings by severity
        let mut critical = Vec::new();
        let mut high = Vec::new();
        let mut medium = Vec::new();
        let mut low = Vec::new();
        let mut info = Vec::new();
        
        for finding in self.documented_findings.values() {
            match finding.severity {
                FindingSeverity::Critical => critical.push(finding),
                FindingSeverity::High => high.push(finding),
                FindingSeverity::Medium => medium.push(finding),
                FindingSeverity::Low => low.push(finding),
                FindingSeverity::Info => info.push(finding),
            }
        }
        
        // Write summary report
        writeln!(file, "# Security Assessment Summary Report")?;
        writeln!(file, "Generated: {}\n", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"))?;
        
        writeln!(file, "## Findings Overview")?;
        writeln!(file, "| Severity | Count |")?;
        writeln!(file, "|----------|-------|")?;
        writeln!(file, "| Critical | {} |", critical.len())?;
        writeln!(file, "| High     | {} |", high.len())?;
        writeln!(file, "| Medium   | {} |", medium.len())?;
        writeln!(file, "| Low      | {} |", low.len())?;
        writeln!(file, "| Info     | {} |", info.len())?;
        writeln!(file, "| **Total**    | **{}** |", 
                 critical.len() + high.len() + medium.len() + low.len() + info.len())?;
        writeln!(file, "")?;
        
        // Write finding details by severity
        for (severity, findings) in [
            ("Critical", critical),
            ("High", high),
            ("Medium", medium),
            ("Low", low),
            ("Info", info),
        ] {
            if !findings.is_empty() {
                writeln!(file, "## {} Findings", severity)?;
                writeln!(file, "")?;
                
                for finding in findings {
                    writeln!(file, "### {} ({})", finding.title, finding.id)?;
                    writeln!(file, "{}", finding.description)?;
                    writeln!(file, "")?;
                }
            }
        }
        
        Ok(())
    }
}

/// Extracts target domain/IP from a command string
fn extract_target_from_command(command: &str) -> Option<String> {
    // Simple heuristic - grab the last term which looks like a domain or IP
    let terms: Vec<&str> = command.split_whitespace().collect();
    
    // Patterns to match domains and IPs
    let domain_pattern = Regex::new(r"^[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z0-9]+(?:\.[a-zA-Z0-9]+)*$").unwrap();
    let ip_pattern = Regex::new(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$").unwrap();
    
    for term in terms.iter().rev() {
        if domain_pattern.is_match(term) || ip_pattern.is_match(term) {
            return Some(term.to_string());
        }
    }
    
    None
} 