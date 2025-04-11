use std::process::{Command, Stdio};
use std::io::{BufReader, BufRead};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio::task;
use anyhow::{Result, Context, anyhow};
use std::path::PathBuf;
use std::fs::{self, OpenOptions};
use std::io::Write;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use uuid::Uuid;

/// Represents a command that is either running or completed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoredCommand {
    pub id: String,
    pub command: String,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub status: CommandStatus,
    pub output_file: PathBuf,
    pub results_summary: Option<String>,
    pub findings: Vec<SecurityFinding>,
    pub command_type: CommandType,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CommandStatus {
    Running,
    Completed,
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CommandType {
    Reconnaissance,
    Scanning,
    Exploitation,
    Documentation,
    Generic,
    Vulnerability,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFinding {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: FindingSeverity,
    pub command_id: String,
    pub raw_output: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FindingSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// Monitors and manages command execution
#[derive(Clone)]
pub struct CommandMonitor {
    work_dir: PathBuf,
    active_commands: Arc<Mutex<Vec<MonitoredCommand>>>,
    output_channel: Arc<Mutex<(mpsc::Sender<CommandOutput>, mpsc::Receiver<CommandOutput>)>>,
    finding_channel: Arc<Mutex<(mpsc::Sender<SecurityFinding>, mpsc::Receiver<SecurityFinding>)>>,
}

#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub command_id: String,
    pub line: String,
    pub is_error: bool,
}

impl CommandMonitor {
    pub fn new(work_dir: PathBuf) -> Result<Self> {
        // Create work directory if it doesn't exist
        fs::create_dir_all(&work_dir)?;
        
        // Create output directory
        let output_dir = work_dir.join("command_output");
        fs::create_dir_all(&output_dir)?;
        
        // Create channel for command output
        let output_channel = Arc::new(Mutex::new(mpsc::channel::<CommandOutput>(100)));
        
        // Create channel for security findings
        let finding_channel = Arc::new(Mutex::new(mpsc::channel::<SecurityFinding>(100)));
        
        Ok(Self {
            work_dir,
            active_commands: Arc::new(Mutex::new(Vec::new())),
            output_channel,
            finding_channel,
        })
    }
    
    /// Executes a command and monitors its output
    pub async fn execute_command(&self, command: &str, command_type: CommandType) -> Result<String> {
        // Validate the command before execution
        let validated_command = self.validate_and_fix_command(command)?;
        
        // Generate unique ID for this command
        let command_id = Uuid::new_v4().to_string();
        
        // Create output file
        let output_file = self.work_dir
            .join("command_output")
            .join(format!("{}_{}.log", chrono::Utc::now().format("%Y%m%d_%H%M%S"), command_id));
        
        // Create command record
        let monitored_command = MonitoredCommand {
            id: command_id.clone(),
            command: validated_command.clone(),
            start_time: chrono::Utc::now(),
            end_time: None,
            status: CommandStatus::Running,
            output_file: output_file.clone(),
            results_summary: None,
            findings: Vec::new(),
            command_type,
        };
        
        // Store command in active commands
        {
            let mut commands = self.active_commands.lock().unwrap();
            commands.push(monitored_command.clone());
        }
        
        // Clone the output sender for the spawned tasks
        let output_tx = self.output_channel.lock().unwrap().0.clone();
        
        // Open output file for writing
        let output_file_handler = Arc::new(Mutex::new(
            OpenOptions::new()
                .create(true)
                .write(true)
                .append(true)
                .open(&output_file)?
        ));
        
        // Log that we're executing the command
        println!("\n=== Executing command: {} ===\n", validated_command);
        
        // Create a process that captures stdout and stderr
        let mut process = Command::new("bash")
            .arg("-c")
            .arg(&validated_command)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context(format!("Failed to spawn command process: {}", validated_command))?;
        
        // Capture stdout
        let stdout = process.stdout.take()
            .context("Failed to capture stdout")?;
        
        let stdout_reader = BufReader::new(stdout);
        let stdout_tx = output_tx.clone();
        let stdout_cmd_id = command_id.clone();
        let stdout_file = output_file_handler.clone();
        
        task::spawn(async move {
            for line in stdout_reader.lines() {
                if let Ok(line) = line {
                    // Log to file
                    if let Ok(mut file) = stdout_file.lock() {
                        let _ = writeln!(file, "[STDOUT] {}", line);
                    }
                    
                    // Send to channel
                    let output = CommandOutput {
                        command_id: stdout_cmd_id.clone(),
                        line: line.clone(),
                        is_error: false,
                    };
                    
                    if let Err(e) = stdout_tx.send(output).await {
                        eprintln!("Error sending command output: {}", e);
                    }
                }
            }
        });
        
        // Capture stderr
        let stderr = process.stderr.take()
            .context("Failed to capture stderr")?;
        
        let stderr_reader = BufReader::new(stderr);
        let stderr_tx = output_tx.clone();
        let stderr_cmd_id = command_id.clone();
        let stderr_file = output_file_handler.clone();
        
        task::spawn(async move {
            for line in stderr_reader.lines() {
                if let Ok(line) = line {
                    // Log to file
                    if let Ok(mut file) = stderr_file.lock() {
                        let _ = writeln!(file, "[STDERR] {}", line);
                    }
                    
                    // Send to channel
                    let output = CommandOutput {
                        command_id: stderr_cmd_id.clone(),
                        line: line.clone(),
                        is_error: true,
                    };
                    
                    if let Err(e) = stderr_tx.send(output).await {
                        eprintln!("Error sending command error output: {}", e);
                    }
                }
            }
        });
        
        // Clone for task
        let active_commands = self.active_commands.clone();
        let cmd_id = command_id.clone();
        
        // Spawn a task to wait for process completion
        task::spawn(async move {
            match process.wait() {
                Ok(status) => {
                    // Update command status
                    let mut commands = active_commands.lock().unwrap();
                    if let Some(cmd) = commands.iter_mut().find(|cmd| cmd.id == cmd_id) {
                        cmd.end_time = Some(chrono::Utc::now());
                        
                        if status.success() {
                            cmd.status = CommandStatus::Completed;
                        } else {
                            cmd.status = CommandStatus::Failed(format!("Command exited with code: {}", status));
                        }
                    }
                },
                Err(e) => {
                    // Update command status with error
                    let mut commands = active_commands.lock().unwrap();
                    if let Some(cmd) = commands.iter_mut().find(|cmd| cmd.id == cmd_id) {
                        cmd.end_time = Some(chrono::Utc::now());
                        cmd.status = CommandStatus::Failed(format!("Error waiting for command: {}", e));
                    }
                }
            }
        });
        
        Ok(command_id)
    }
    
    /// Validates and fixes commands to prevent privilege issues
    fn validate_and_fix_command(&self, command: &str) -> Result<String> {
        // Trim the command to remove leading/trailing whitespace
        let command = command.trim();
        
        // Command must not be empty
        if command.is_empty() {
            return Err(anyhow!("Empty command"));
        }
        
        let mut fixed_command = command.to_string();
        
        // Check if command is explanatory text
        let explanatory_markers = [
            "try this", "this will", "command:", "run this", "executing:",
            "scan just", "lay of the land", "scan finishes", "tell me what", 
            "we can", "you can", "let's", "while that's", "once the", 
            "get a", "gives us", "let me know", "execute this", "we'll",
            "you'll", "finished", "finishes", "look for", "find out"
        ];
        
        for marker in &explanatory_markers {
            if fixed_command.to_lowercase().contains(marker) {
                return Err(anyhow!("This appears to be explanatory text, not a command: '{}'", marker));
            }
        }
        
        // Fix common command issues
        
        // 1. Fix nmap SYN scan (-sS) which requires root
        if command.contains("nmap") && command.contains(" -sS") && !command.starts_with("sudo ") {
            // Replace with TCP connect scan (-sT) which doesn't require root
            fixed_command = fixed_command.replace(" -sS", " -sT");
        }
        
        // 2. Check for other nmap scans that require privileges
        if command.contains("nmap") && (command.contains(" -sU") || command.contains(" -sN") || 
                                        command.contains(" -sF") || command.contains(" -sX")) 
            && !command.starts_with("sudo ") {
            // Add a comment explaining why the command was modified
            return Err(anyhow!("This scan type requires root privileges. Try using 'sudo' or switch to '-sT' for unprivileged scanning."));
        }
        
        // 3. Validate the command structure for nmap
        if fixed_command.starts_with("nmap") || fixed_command.starts_with("sudo nmap") {
            // Check that it has a valid target
            if !fixed_command.contains(".com") && !fixed_command.contains(".net") && 
               !fixed_command.contains(".org") && !fixed_command.contains(".edu") && 
               !fixed_command.contains(".gov") && !fixed_command.contains(".io") && 
               !fixed_command.contains(".co") && !fixed_command.contains(" localhost") && 
               !fixed_command.contains(" 127.0.0.1") && !fixed_command.contains(" 10.") && 
               !fixed_command.contains(" 192.168.") && !fixed_command.contains(" 172.") {
                return Err(anyhow!("Nmap command appears to be missing a valid target"));
            }
        }
        
        // 4. Validate that the command binary exists (for common commands)
        let common_tools = ["nmap", "dig", "whois", "ping", "traceroute", "gobuster", "ffuf", "dirb"];
        for tool in common_tools {
            if fixed_command.starts_with(tool) || fixed_command.starts_with(&format!("sudo {}", tool)) {
                let check_cmd = Command::new("which")
                    .arg(tool)
                    .output()
                    .context(format!("Failed to check if {} is installed", tool))?;
                
                if !check_cmd.status.success() {
                    return Err(anyhow!("Tool '{}' is not installed or not in PATH", tool));
                }
            }
        }
        
        Ok(fixed_command)
    }
    
    /// Get output receiver for consuming command output
    pub fn get_output_receiver(&self) -> mpsc::Receiver<CommandOutput> {
        let mut channel_lock = self.output_channel.lock().unwrap();
        let (_new_tx, new_rx) = mpsc::channel(100);
        let old_rx = std::mem::replace(&mut channel_lock.1, new_rx);
        old_rx
    }
    
    /// Get findings receiver for consuming security findings
    pub fn get_findings_receiver(&self) -> mpsc::Receiver<SecurityFinding> {
        let mut channel_lock = self.finding_channel.lock().unwrap();
        let (_new_tx, new_rx) = mpsc::channel(100);
        let old_rx = std::mem::replace(&mut channel_lock.1, new_rx);
        old_rx
    }
    
    /// Get command by ID
    pub fn get_command(&self, id: &str) -> Option<MonitoredCommand> {
        let commands = self.active_commands.lock().unwrap();
        commands.iter().find(|cmd| cmd.id == id).cloned()
    }
    
    /// Get all active commands
    pub fn get_active_commands(&self) -> Vec<MonitoredCommand> {
        let commands = self.active_commands.lock().unwrap();
        commands.iter()
            .filter(|cmd| matches!(cmd.status, CommandStatus::Running))
            .cloned()
            .collect()
    }
    
    /// Get all commands
    pub fn get_all_commands(&self) -> Vec<MonitoredCommand> {
        let commands = self.active_commands.lock().unwrap();
        commands.clone()
    }
    
    /// Add a finding to a command
    pub async fn add_finding(&self, finding: SecurityFinding) -> Result<()> {
        // Add finding to command
        {
            let mut commands = self.active_commands.lock().unwrap();
            if let Some(cmd) = commands.iter_mut().find(|cmd| cmd.id == finding.command_id) {
                cmd.findings.push(finding.clone());
            }
        }
        
        // Send finding to channel - get the sender before await
        let sender = {
            let guard = self.finding_channel.lock().unwrap();
            guard.0.clone()
        };
        
        // Now send without holding the lock
        if let Err(e) = sender.send(finding).await {
            return Err(anyhow!("Failed to send finding: {}", e));
        }
        
        Ok(())
    }
    
    /// Update command summary
    pub fn update_command_summary(&self, id: &str, summary: &str) -> Result<()> {
        let mut commands = self.active_commands.lock().unwrap();
        if let Some(cmd) = commands.iter_mut().find(|cmd| cmd.id == id) {
            cmd.results_summary = Some(summary.to_string());
            Ok(())
        } else {
            Err(anyhow!("Command not found: {}", id))
        }
    }
    
    /// Save all findings to a report file
    pub fn generate_findings_report(&self, output_file: &PathBuf) -> Result<()> {
        let commands = self.active_commands.lock().unwrap();
        
        // Collect all findings
        let mut all_findings = Vec::new();
        for cmd in commands.iter() {
            for finding in &cmd.findings {
                all_findings.push((cmd, finding));
            }
        }
        
        // Sort findings by severity
        all_findings.sort_by(|(_, a), (_, b)| {
            let severity_order = |s: &FindingSeverity| -> u8 {
                match s {
                    FindingSeverity::Critical => 0,
                    FindingSeverity::High => 1,
                    FindingSeverity::Medium => 2,
                    FindingSeverity::Low => 3,
                    FindingSeverity::Info => 4,
                }
            };
            
            severity_order(&a.severity).cmp(&severity_order(&b.severity))
        });
        
        // Generate report
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(output_file)?;
        
        writeln!(file, "# Security Findings Report")?;
        writeln!(file, "Generated: {}\n", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"))?;
        
        for (severity, findings) in [
            FindingSeverity::Critical,
            FindingSeverity::High,
            FindingSeverity::Medium,
            FindingSeverity::Low,
            FindingSeverity::Info,
        ].iter().map(|sev| {
            (sev, all_findings.iter().filter(|(_, f)| f.severity == *sev).collect::<Vec<_>>())
        }) {
            if !findings.is_empty() {
                writeln!(file, "## {:?} Findings ({})", severity, findings.len())?;
                
                for (cmd, finding) in findings {
                    writeln!(file, "### {}", finding.title)?;
                    writeln!(file, "**ID:** {}", finding.id)?;
                    writeln!(file, "**Description:** {}", finding.description)?;
                    writeln!(file, "**Command:** {}", cmd.command)?;
                    writeln!(file, "**Discovered:** {}", finding.timestamp.format("%Y-%m-%d %H:%M:%S UTC"))?;
                    writeln!(file, "**Raw Output:**\n```\n{}\n```\n", finding.raw_output)?;
                }
                
                writeln!(file, "")?;
            }
        }
        
        Ok(())
    }
    
    /// Wait for a command to complete with timeout
    pub async fn wait_for_command_completion(&self, cmd_id: &str, timeout_seconds: u64) -> bool {
        let mut attempts = 0;
        let max_attempts = timeout_seconds;
        
        loop {
            if let Some(cmd_status) = self.get_command(cmd_id) {
                if !matches!(cmd_status.status, CommandStatus::Running) {
                    // Command completed
                    return true;
                }
            } else {
                // Command not found
                return false;
            }
            
            attempts += 1;
            if attempts >= max_attempts {
                // Timeout reached
                return false;
            }
            
            // Wait a second before checking again
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
    }
    
    /// Terminate a running command
    pub async fn terminate_command(&self, cmd_id: &str) -> Result<()> {
        // Find the command
        let cmd_opt = self.get_command(cmd_id);
        
        if let Some(cmd) = cmd_opt {
            if let CommandStatus::Running = cmd.status {
                // Find process by command
                let ps_output = Command::new("ps")
                    .arg("-ef")
                    .output()
                    .context("Failed to execute ps command")?;
                
                let ps_output = String::from_utf8_lossy(&ps_output.stdout);
                
                // Look for the command in ps output
                for line in ps_output.lines() {
                    if line.contains(&cmd.command) {
                        // Extract PID (2nd column)
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 2 {
                            if let Ok(pid) = parts[1].parse::<u32>() {
                                // Kill the process
                                let _ = Command::new("kill")
                                    .arg("-TERM")
                                    .arg(format!("{}", pid))
                                    .output();
                                
                                // Update command status
                                {
                                    let mut commands = self.active_commands.lock().unwrap();
                                    for cmd in commands.iter_mut() {
                                        if cmd.id == cmd_id {
                                            cmd.status = CommandStatus::Failed("Terminated by user".to_string());
                                            cmd.end_time = Some(chrono::Utc::now());
                                            break;
                                        }
                                    }
                                }
                                
                                return Ok(());
                            }
                        }
                    }
                }
            }
        }
        
        Err(anyhow!("Could not find running command with ID: {}", cmd_id))
    }
}

/// Helper function to create a new security finding
pub fn create_finding(
    title: &str,
    description: &str,
    severity: FindingSeverity,
    command_id: &str,
    raw_output: &str,
) -> SecurityFinding {
    SecurityFinding {
        id: Uuid::new_v4().to_string(),
        title: title.to_string(),
        description: description.to_string(),
        severity,
        command_id: command_id.to_string(),
        raw_output: raw_output.to_string(),
        timestamp: chrono::Utc::now(),
    }
} 