use std::sync::Arc;
use anyhow::{Result, Context};
use tokio::sync::mpsc;
use std::process::{Command, Stdio};
use std::time::Duration;

use super::command_monitor::CommandMonitor;
use super::auto_documentation::{FollowUpAction, ActionStatus};

/// Executes follow-up actions based on security findings
pub struct ActionExecutor {
    monitor: Arc<CommandMonitor>,
    action_rx: mpsc::Receiver<FollowUpAction>,
    result_tx: mpsc::Sender<FollowUpAction>,
    running: bool,
    max_concurrent: usize,
    current_executing: usize,
}

impl ActionExecutor {
    pub fn new(
        monitor: Arc<CommandMonitor>,
        action_rx: mpsc::Receiver<FollowUpAction>,
        result_tx: mpsc::Sender<FollowUpAction>,
        max_concurrent: usize
    ) -> Self {
        Self {
            monitor,
            action_rx,
            result_tx,
            running: false,
            max_concurrent,
            current_executing: 0,
        }
    }
    
    /// Start the action executor
    pub async fn start(&mut self) -> Result<()> {
        if self.running {
            return Ok(());
        }
        
        self.running = true;
        
        // Main execution loop
        while let Some(action) = self.action_rx.recv().await {
            // Skip already completed or failed actions
            if action.status == ActionStatus::Completed || action.status == ActionStatus::Failed {
                continue;
            }
            
            // Wait if we're at max concurrent actions
            while self.current_executing >= self.max_concurrent {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            
            // Increment executing count
            self.current_executing += 1;
            
            // Clone necessary data for the async task
            let result_tx = self.result_tx.clone();
            let mut action_copy = action.clone();
            
            // Execute action in a separate task
            tokio::spawn(async move {
                // Update status to in-progress
                action_copy.status = ActionStatus::InProgress;
                
                // Execute the command if present
                if let Some(cmd) = &action_copy.command {
                    match execute_command(cmd).await {
                        Ok(output) => {
                            // Update action with result
                            action_copy.result = Some(output);
                            action_copy.status = ActionStatus::Completed;
                        },
                        Err(e) => {
                            // Update action with error
                            action_copy.result = Some(format!("ERROR: {}", e));
                            action_copy.status = ActionStatus::Failed;
                        }
                    }
                } else {
                    // No command to execute, just mark as completed
                    action_copy.status = ActionStatus::Completed;
                }
                
                // Send the updated action back
                if let Err(e) = result_tx.send(action_copy).await {
                    eprintln!("Failed to send action result: {}", e);
                }
            });
        }
        
        self.running = false;
        Ok(())
    }
}

/// Execute a command and capture its output
async fn execute_command(command: &str) -> Result<String> {
    println!("Executing follow-up action: {}", command);
    
    // Create and execute the process
    let output = Command::new("bash")
        .arg("-c")
        .arg(command)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("Failed to execute command")?;
    
    // Combine stdout and stderr
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    
    let mut combined = String::new();
    
    if !stdout.is_empty() {
        combined.push_str("=== STDOUT ===\n");
        combined.push_str(&stdout);
        combined.push_str("\n");
    }
    
    if !stderr.is_empty() {
        combined.push_str("=== STDERR ===\n");
        combined.push_str(&stderr);
    }
    
    Ok(combined)
} 