use std::process::Stdio;
use anyhow::{Result, Context};
use std::collections::HashMap;
use tokio::process::Command as TokioCommand;
use serde::{Serialize, Deserialize};
use regex::Regex;

// Define security command types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CommandType {
    Reconnaissance,
    Scanning,
    Vulnerability,
    Exploitation,
    PostExploitation,
    Generic,
}

// Structure to hold command metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityCommand {
    pub name: String,
    pub description: String,
    pub command_type: CommandType,
    pub template: String,
    pub default_args: Vec<String>,
    pub requires_sudo: bool,
}

// Security command executor
pub struct SecurityCommandExecutor {
    command_templates: HashMap<String, SecurityCommand>,
    last_output: Option<String>,
}

impl SecurityCommandExecutor {
    pub fn new() -> Self {
        let mut executor = Self {
            command_templates: HashMap::new(),
            last_output: None,
        };
        
        // Initialize with common security tools
        executor.register_default_commands();
        
        executor
    }
    
    fn register_default_commands(&mut self) {
        // Nmap scanning commands
        self.register_command(SecurityCommand {
            name: "nmap_basic".to_string(),
            description: "Basic Nmap scan".to_string(),
            command_type: CommandType::Reconnaissance,
            template: "nmap {target}".to_string(),
            default_args: vec![],
            requires_sudo: false,
        });
        
        self.register_command(SecurityCommand {
            name: "nmap_service".to_string(),
            description: "Nmap service and version detection".to_string(),
            command_type: CommandType::Reconnaissance,
            template: "nmap -sV {target}".to_string(),
            default_args: vec![],
            requires_sudo: false,
        });
        
        self.register_command(SecurityCommand {
            name: "nmap_all_ports".to_string(),
            description: "Nmap scan of all ports".to_string(),
            command_type: CommandType::Reconnaissance,
            template: "nmap -p- {target}".to_string(),
            default_args: vec![],
            requires_sudo: false,
        });
        
        // Subdomain enumeration
        self.register_command(SecurityCommand {
            name: "sublist3r".to_string(),
            description: "Subdomain enumeration with Sublist3r".to_string(),
            command_type: CommandType::Reconnaissance,
            template: "sublist3r -d {target}".to_string(),
            default_args: vec![],
            requires_sudo: false,
        });
        
        // Web scanning
        self.register_command(SecurityCommand {
            name: "nikto".to_string(),
            description: "Web server scanner".to_string(),
            command_type: CommandType::Vulnerability,
            template: "nikto -h {target}".to_string(),
            default_args: vec![],
            requires_sudo: false,
        });
        
        // XSS testing tools
        self.register_command(SecurityCommand {
            name: "xsser".to_string(),
            description: "XSS vulnerability scanner".to_string(),
            command_type: CommandType::Vulnerability,
            template: "xsser --url {target}".to_string(),
            default_args: vec![],
            requires_sudo: false,
        });
        
        self.register_command(SecurityCommand {
            name: "dalfox".to_string(),
            description: "Parameter analyzer and XSS scanner".to_string(),
            command_type: CommandType::Vulnerability,
            template: "dalfox url {target}".to_string(),
            default_args: vec![],
            requires_sudo: false,
        });
        
        // Web crawling and directory scanning
        self.register_command(SecurityCommand {
            name: "dirsearch".to_string(),
            description: "Web path discovery".to_string(),
            command_type: CommandType::Reconnaissance,
            template: "dirsearch -u {target}".to_string(),
            default_args: vec![],
            requires_sudo: false,
        });
        
        // Generic command
        self.register_command(SecurityCommand {
            name: "generic".to_string(),
            description: "Generic command execution".to_string(),
            command_type: CommandType::Generic,
            template: "{command}".to_string(),
            default_args: vec![],
            requires_sudo: false,
        });
    }
    
    pub fn register_command(&mut self, command: SecurityCommand) {
        self.command_templates.insert(command.name.clone(), command);
    }
    
    pub fn get_command(&self, name: &str) -> Option<&SecurityCommand> {
        self.command_templates.get(name)
    }
    
    pub fn get_last_output(&self) -> Option<&String> {
        self.last_output.as_ref()
    }
    
    // Parse intent from user message and determine relevant security command
    pub fn suggest_command_from_intent(&self, user_message: &str) -> Option<(String, HashMap<String, String>)> {
        let user_message = user_message.to_lowercase();
        
        // XSS vulnerability scanning
        if (user_message.contains("xss") || user_message.contains("cross site scripting")) && 
           (user_message.contains("scan") || user_message.contains("check") || user_message.contains("test")) {
            
            // Extract target domain
            let domain = extract_domain(&user_message)?;
            
            let mut params = HashMap::new();
            params.insert("target".to_string(), domain);
            
            // Choose the XSS scanner tool based on the message
            if user_message.contains("dalfox") {
                return Some(("dalfox".to_string(), params));
            } else {
                return Some(("xsser".to_string(), params));
            }
        }
        
        // Port scanning
        if user_message.contains("port") && 
           (user_message.contains("scan") || user_message.contains("check") || user_message.contains("enumerate")) {
            
            let domain = extract_domain(&user_message)?;
            
            let mut params = HashMap::new();
            params.insert("target".to_string(), domain);
            
            // Determine type of port scan
            if user_message.contains("all ports") || user_message.contains("full") {
                return Some(("nmap_all_ports".to_string(), params));
            } else if user_message.contains("service") || user_message.contains("version") {
                return Some(("nmap_service".to_string(), params));
            } else {
                return Some(("nmap_basic".to_string(), params));
            }
        }
        
        // Subdomain enumeration
        if (user_message.contains("subdomain") || user_message.contains("sub-domain")) && 
           (user_message.contains("find") || user_message.contains("enumerate") || user_message.contains("discover")) {
            
            let domain = extract_domain(&user_message)?;
            
            let mut params = HashMap::new();
            params.insert("target".to_string(), domain);
            
            return Some(("sublist3r".to_string(), params));
        }
        
        // Directory/path discovery
        if (user_message.contains("directory") || user_message.contains("path") || user_message.contains("endpoint")) && 
           (user_message.contains("scan") || user_message.contains("discover") || user_message.contains("find")) {
            
            let domain = extract_domain(&user_message)?;
            
            let mut params = HashMap::new();
            params.insert("target".to_string(), domain);
            
            return Some(("dirsearch".to_string(), params));
        }
        
        // Web vulnerability scanning
        if (user_message.contains("web") || user_message.contains("website") || user_message.contains("http")) && 
           (user_message.contains("vulnerability") || user_message.contains("scan") || user_message.contains("security")) {
            
            let domain = extract_domain(&user_message)?;
            
            let mut params = HashMap::new();
            params.insert("target".to_string(), domain);
            
            return Some(("nikto".to_string(), params));
        }
        
        // Try to extract a generic command
        if user_message.contains("run") || user_message.contains("execute") {
            if let Some(command) = extract_command(&user_message) {
                let mut params = HashMap::new();
                params.insert("command".to_string(), command);
                
                return Some(("generic".to_string(), params));
            }
        }
        
        None
    }
    
    pub async fn execute_command(&mut self, name: &str, params: &HashMap<String, String>) -> Result<String> {
        let command_template = self.command_templates.get(name)
            .context(format!("Command template '{}' not found", name))?;
        
        // Prepare the command by replacing placeholders with parameters
        let mut command_str = command_template.template.clone();
        
        for (key, value) in params {
            command_str = command_str.replace(&format!("{{{}}}", key), value);
        }
        
        // Execute the command
        println!("Executing: {}", command_str);
        
        // Create a new terminal window for command execution
        self.launch_terminal_command(&command_str).await?;
        
        // Store the command string as output (we don't actually capture output from the terminal window)
        self.last_output = Some(format!("Executed: {}", command_str));
        
        Ok(self.last_output.clone().unwrap())
    }
    
    async fn launch_terminal_command(&self, command: &str) -> Result<()> {
        // Create a command that opens a new terminal window and executes our command
        let terminal_cmd = format!(
            "x-terminal-emulator -e 'bash -c \"echo [Hacksor] Executing: {} && {} || echo [ERROR] Command failed with error code $?; echo Press Enter to close...; read\"'",
            command, command
        );
        
        TokioCommand::new("bash")
            .arg("-c")
            .arg(terminal_cmd)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("Failed to execute command in a new terminal")?;
        
        // Sleep briefly to allow the terminal to open
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        
        Ok(())
    }
}

// Helper function to extract domain name from a message
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

// Helper function to extract a command from a user message
fn extract_command(message: &str) -> Option<String> {
    // Look for quoted commands like 'nmap example.com' or "nmap example.com"
    let quoted_regex = Regex::new(r#"['"]([^'"]+)['"]"#).ok()?;
    
    if let Some(captures) = quoted_regex.captures(message) {
        if let Some(cmd_match) = captures.get(1) {
            return Some(cmd_match.as_str().to_string());
        }
    }
    
    // Look for commands after "run" or "execute"
    let run_regex = Regex::new(r"(?:run|execute)\s+(.+?)(?:$|\s+(?:on|against))").ok()?;
    
    if let Some(captures) = run_regex.captures(message) {
        if let Some(cmd_match) = captures.get(1) {
            return Some(cmd_match.as_str().to_string());
        }
    }
    
    None
} 