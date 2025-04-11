use anyhow::Result;
use std::process::{Command, Output};
use std::path::PathBuf;
use std::fs;

pub mod command_monitor;
pub mod output_analyzer;
pub mod auto_documentation;
pub mod action_executor;

pub use command_monitor::{
    CommandMonitor, CommandStatus, CommandType
};
pub use auto_documentation::ActionStatus;
pub use action_executor::ActionExecutor;

#[derive(Clone)]
pub struct TerminalManager {
    work_dir: PathBuf,
    command_monitor: CommandMonitor,
}

impl TerminalManager {
    pub fn new(work_dir: PathBuf) -> Result<Self> {
        if !work_dir.exists() {
            fs::create_dir_all(&work_dir)?;
        }
        
        let command_monitor = CommandMonitor::new(work_dir.clone())?;
        
        Ok(Self {
            work_dir,
            command_monitor,
        })
    }

    pub async fn execute_command(&self, command: &str, args: &[&str]) -> Result<Output> {
        let output = Command::new(command)
            .args(args)
            .current_dir(&self.work_dir)
            .output()?;

        Ok(output)
    }

    pub async fn execute_script(&self, script_path: &str) -> Result<Output> {
        let output = Command::new("bash")
            .arg(script_path)
            .current_dir(&self.work_dir)
            .output()?;

        Ok(output)
    }

    pub fn get_working_dir(&self) -> &PathBuf {
        &self.work_dir
    }
    
    /// Get the command monitor instance
    pub fn get_command_monitor(&self) -> CommandMonitor {
        self.command_monitor.clone()
    }
    
    /// Execute a monitored command with output analysis
    pub async fn execute_monitored_command(&self, command: &str, command_type: CommandType) -> Result<String> {
        self.command_monitor.execute_command(command, command_type).await
    }
}

#[allow(dead_code)]
pub struct CommandResult {
    pub success: bool,
    pub output: String,
    pub error: String,
}

impl From<Output> for CommandResult {
    fn from(output: Output) -> Self {
        Self {
            success: output.status.success(),
            output: String::from_utf8_lossy(&output.stdout).into_owned(),
            error: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }
}

pub use auto_documentation::AutoDocumentation;
pub use output_analyzer::OutputAnalyzer; 