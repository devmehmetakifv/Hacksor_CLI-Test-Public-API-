use std::sync::Arc;
use async_trait::async_trait;
use anyhow::Result;

pub mod security_commands;

// Re-export security command related types
pub use security_commands::SecurityCommandExecutor;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Target {
    pub domain: String,
    pub scope: Vec<String>,
    pub excluded: Vec<String>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PentestSession {
    pub target: Target,
    pub session_id: String,
    pub status: SessionStatus,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum SessionStatus {
    Initialized,
    Reconnaissance,
    VulnerabilityAssessment,
    Exploitation,
    Completed,
    Failed(String),
}

#[async_trait]
#[allow(dead_code)]
pub trait PentestModule {
    async fn initialize(&mut self, target: &Target) -> Result<()>;
    async fn execute(&mut self) -> Result<()>;
    async fn finalize(&mut self) -> Result<()>;
    fn get_name(&self) -> &str;
}

#[allow(dead_code)]
pub struct PentestEngine {
    modules: Vec<Box<dyn PentestModule>>,
    current_session: Option<Arc<PentestSession>>,
    command_executor: SecurityCommandExecutor,
}

impl PentestEngine {
    pub fn new() -> Self {
        Self {
            modules: Vec::new(),
            current_session: None,
            command_executor: SecurityCommandExecutor::new(),
        }
    }

    pub fn add_module(&mut self, module: Box<dyn PentestModule>) {
        self.modules.push(module);
    }

    pub async fn start_session(&mut self, target: Target) -> Result<()> {
        let session = PentestSession {
            target,
            session_id: uuid::Uuid::new_v4().to_string(),
            status: SessionStatus::Initialized,
        };
        
        self.current_session = Some(Arc::new(session));
        Ok(())
    }

    pub async fn run_modules(&mut self) -> Result<()> {
        if let Some(session) = &self.current_session {
            for module in &mut self.modules {
                module.initialize(&session.target).await?;
                module.execute().await?;
                module.finalize().await?;
            }
        }
        Ok(())
    }
    
    // New methods for security command execution
    
    pub fn get_command_executor(&mut self) -> &mut SecurityCommandExecutor {
        &mut self.command_executor
    }
    
    pub async fn execute_security_command_from_intent(&mut self, user_message: &str) -> Result<Option<String>> {
        // Try to determine command from user intent
        if let Some((command_name, params)) = self.command_executor.suggest_command_from_intent(user_message) {
            let output = self.command_executor.execute_command(&command_name, &params).await?;
            Ok(Some(output))
        } else {
            Ok(None)
        }
    }
} 