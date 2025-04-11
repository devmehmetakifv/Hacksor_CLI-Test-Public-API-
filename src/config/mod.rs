use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use anyhow::Result;

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub api_key: String,
    pub working_dir: PathBuf,
    pub tools: Vec<ToolConfig>,
    pub rate_limit: RateLimitConfig,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ToolConfig {
    pub name: String,
    pub path: PathBuf,
    pub args: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub requests_per_minute: u32,
    pub concurrent_connections: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            api_key: String::new(),
            working_dir: PathBuf::from("sessions"),
            tools: Vec::new(),
            rate_limit: RateLimitConfig {
                requests_per_minute: 60,
                concurrent_connections: 10,
            },
        }
    }
}

impl Config {
    #[allow(dead_code)]
    pub fn load(path: &PathBuf) -> Result<Self> {
        let config = if path.exists() {
            let content = std::fs::read_to_string(path)?;
            toml::from_str(&content)?
        } else {
            Config::default()
        };
        
        Ok(config)
    }
    
    #[allow(dead_code)]
    pub fn save(&self, path: &PathBuf) -> Result<()> {
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
} 