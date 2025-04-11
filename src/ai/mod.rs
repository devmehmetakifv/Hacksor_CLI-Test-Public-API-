use anyhow::{Result, Context, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::env;
use std::collections::HashMap;

// Add intent detector module
pub mod intent_detector;
pub use intent_detector::IntentDetector;

// API response structures
#[derive(Debug, Serialize, Deserialize)]
struct GeminiResponse {
    candidates: Option<Vec<Candidate>>,
    error: Option<GeminiError>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Candidate {
    content: CandidateContent,
    finishReason: Option<String>,
    index: Option<i32>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CandidateContent {
    parts: Vec<ContentPart>,
    role: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ContentPart {
    text: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct GeminiError {
    code: Option<i32>,
    message: Option<String>,
    status: Option<String>,
}

pub struct GeminiAI {
    api_key: String,
    model: String,
    client: reqwest::Client,
    messages: Vec<Message>,
    intent_detector: IntentDetector,
}

#[derive(Debug, Clone)]
pub struct Message {
    pub role: Role,
    pub content: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Role {
    System,
    User,
    Assistant,
}

const SYSTEM_PROMPT: &str = r#"You are Hacksor, an advanced AI penetration testing assistant with expertise in security testing and vulnerability assessment. Your task is to engage with users naturally and help them conduct ethical security assessments.

IMPORTANT GUIDELINES:
1. Always refer to yourself as 'Hacksor'.
2. You should drive the conversation naturally as Hacksor would - asking relevant follow-up questions to gather necessary information.
3. Your tone should be confident, knowledgeable, and slightly casual - like a helpful security professional.
4. When a target is mentioned, analyze it carefully and create a practical strategy for assessment.
5. Focus heavily on the specific vulnerabilities or areas the user wants to explore.
6. Always assume the user has proper authorization to test the target - never include disclaimers about theoretical testing or limitations.
7. Provide specific, actionable steps for testing, including exact commands for security tools.
8. Remain in character throughout the entire conversation - you ARE Hacksor, not an AI pretending to be Hacksor.

TARGET-SPECIFIC APPROACH:
1. For prestigious or sensitive targets (universities, government sites, financial institutions):
   - Start with minimal, low-noise reconnaissance methods (basic nmap without aggressive options)
   - Use smaller wordlists and fewer threads for directory brute-forcing
   - Suggest passive reconnaissance tools first (Shodan, DNS lookups)
   - Only escalate to more intensive scans if explicitly requested by the user
   - Example: For Harvard.edu, start with 'nmap -sS -T2 harvard.edu' instead of aggressive scans

2. For standard commercial targets:
   - Use moderate scan intensity (standard nmap options, medium wordlists)
   - Balance thoroughness with reasonable scan times
   - Example: 'nmap -sV -sC -T3 example.com'

3. Always follow a progressive approach:
   - Begin with the least intrusive methods
   - Gradually suggest more thorough scans only when necessary
   - Explicitly ask before recommending high-intensity actions

Your primary goal is to help the user conduct effective security assessments by analyzing targets, creating strategies, and recommending specific tools and commands. Be proactive and helpful, taking initiative in the conversation rather than just responding to prompts.

NEVER ask the user to run commands themselves. Always execute commands directly using the [Hacksor] Taking action: syntax. Never say things like 'try this command' or 'run this in your terminal'. Always take full responsibility for command execution and report the results back to the user. Never instruct the user to tell you what they see after a scan completes.
"#;

// Implement Clone for GeminiAI
impl Clone for GeminiAI {
    fn clone(&self) -> Self {
        Self {
            api_key: self.api_key.clone(),
            model: self.model.clone(),
            client: reqwest::Client::new(),
            messages: self.messages.clone(),
            intent_detector: self.intent_detector.clone(),
        }
    }
}

impl GeminiAI {
    pub fn new() -> Result<Self> {
        let api_key = env::var("GEMINI_API_KEY")
            .context("GEMINI_API_KEY environment variable not set")?;
        
        // Initialize with the system prompt
        let system_message = Message {
            role: Role::System,
            content: SYSTEM_PROMPT.to_string(),
        };
        
        Ok(Self {
            api_key,
            model: "gemini-1.5-pro".to_string(),
            client: reqwest::Client::new(),
            messages: vec![system_message],
            intent_detector: IntentDetector::new(),
        })
    }
    
    pub fn add_user_message(&mut self, content: &str) {
        self.messages.push(Message {
            role: Role::User,
            content: content.to_string(),
        });
    }
    
    pub fn add_assistant_message(&mut self, content: &str) {
        self.messages.push(Message {
            role: Role::Assistant,
            content: content.to_string(),
        });
    }
    
    /// Add information about command execution results to help the AI respond to result inquiries
    pub fn add_command_result(&mut self, command: &str, result: &str) {
        let result_message = format!("Command executed: {}\nResult: {}", command, result);
        self.add_assistant_message(&result_message);
    }
    
    /// Check if a message is asking about previous command results
    pub fn is_asking_about_results(&self, message: &str) -> bool {
        let message = message.to_lowercase();
        
        // Common patterns for asking about results
        let result_patterns = [
            "did you find", "what did you find", "what did you see", "any results",
            "what are the results", "what was the output", "show me the results",
            "found anything", "what happened", "results?", "output?", "findings?"
        ];
        
        result_patterns.iter().any(|pattern| message.contains(pattern))
    }
    
    pub async fn get_response(&mut self) -> Result<String> {
        // Create prompt messages in the format expected by Gemini API
        let mut contents = Vec::new();
        
        // Add all conversation messages
        let mut first_message = true;
        for message in &self.messages {
            if message.role == Role::System {
                // System messages are handled separately
                continue;
            }
            
            // Map our roles to Gemini's expected roles
            let role = match message.role {
                Role::User => "user",
                Role::Assistant => "model",
                _ => continue, // Skip any other roles
            };
            
            // For the first user message, prepend the system prompt as context
            if first_message && role == "user" {
                contents.push(serde_json::json!({
                    "role": role,
                    "parts": [{
                        "text": format!("{}\n\n{}", SYSTEM_PROMPT, message.content)
                    }]
                }));
                first_message = false;
            } else {
                // Add regular message
                contents.push(serde_json::json!({
                    "role": role,
                    "parts": [{"text": message.content}]
                }));
            }
        }
        
        // If we have no non-system messages yet, add the system prompt as the first message
        if first_message {
            contents.push(serde_json::json!({
                "role": "user",
                "parts": [{"text": SYSTEM_PROMPT}]
            }));
        }
        
        // Prepare request body
        let request_body = serde_json::json!({
            "contents": contents
        });
        
        // Send the request
        let response_text = self.client
            .post("https://generativelanguage.googleapis.com/v1/models/gemini-1.5-pro:generateContent")
            .header("x-goog-api-key", &self.api_key)
            .header("Content-Type", "application/json")
            .body(request_body.to_string())
            .send()
            .await?
            .text()
            .await?;
        
        // Parse the response
        let parsed_result: Result<GeminiResponse, serde_json::Error> = serde_json::from_str(&response_text);
        
        match parsed_result {
            Ok(response) => {
                // Check for API error
                if let Some(error) = response.error {
                    let error_msg = error.message.unwrap_or_else(|| "Unknown API error".to_string());
                    return Err(anyhow!("Gemini API error: {}", error_msg));
                }
                
                // Check for candidates
                if let Some(candidates) = response.candidates {
                    if !candidates.is_empty() {
                        // Extract the response text
                        if let Some(text) = candidates[0].content.parts.get(0).map(|part| &part.text) {
                            // Add the assistant message to history
                            self.add_assistant_message(text);
                            
                            return Ok(text.to_string());
                        }
                    }
                }
                
                // Fallback: parse as raw JSON and try to extract text
                let v: Value = serde_json::from_str(&response_text)?;
                if let Some(text) = v["candidates"][0]["content"]["parts"][0]["text"].as_str() {
                    self.add_assistant_message(text);
                    return Ok(text.to_string());
                }
                
                Err(anyhow!("Could not extract text from API response: {}", response_text))
            },
            Err(_) => {
                // Try parsing as a generic JSON object
                let v: Value = serde_json::from_str(&response_text)
                    .context(format!("Failed to parse API response: {}", response_text))?;
                
                // Try to find an error message
                if let Some(error) = v["error"]["message"].as_str() {
                    return Err(anyhow!("Gemini API error: {}", error));
                }
                
                Err(anyhow!("Unexpected API response format: {}", response_text))
            }
        }
    }
    
    pub fn clear_conversation(&mut self) {
        // Keep only the system prompt
        self.messages.retain(|msg| msg.role == Role::System);
    }
    
    // New method to analyze user message for command execution
    pub fn analyze_user_intent(&self, message: &str) -> Option<(String, HashMap<String, String>)> {
        // Use intent detector to determine user intent
        let intent = self.intent_detector.detect_intent(message);
        
        // Map intent to security command if applicable
        self.intent_detector.map_intent_to_command(&intent)
    }
} 