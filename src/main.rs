mod core;
mod ai;
mod terminal;
mod config;
mod utils;

use anyhow::Result;
use std::path::PathBuf;
use std::io::{self, Write};
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
    terminal::{Clear, ClearType},
    cursor::{MoveTo}
};
use std::process::Command;
use core::security_commands::SecurityCommandExecutor;
use terminal::{
    TerminalManager, OutputAnalyzer, 
    AutoDocumentation, ActionExecutor, CommandType, CommandStatus
};
use tokio::sync::mpsc;
use std::env;
use regex;
use std::sync::{Arc, Mutex};

#[tokio::main]
async fn main() -> Result<()> {
    // Setup terminal UI
    setup_terminal()?;
    
    // Display welcome message
    display_hacksor_welcome()?;
    
    // Initialize AI
    let mut ai = match ai::GeminiAI::new() {
        Ok(ai) => ai,
        Err(e) => {
            let mut stdout = io::stdout();
            execute!(
                stdout,
                SetForegroundColor(Color::Red),
                Print(format!("\n[ERROR] Failed to initialize AI: {}\n", e)),
                Print("\nMake sure you have set the GEMINI_API_KEY environment variable:\n"),
                SetForegroundColor(Color::Yellow),
                Print("export GEMINI_API_KEY=\"your-api-key\"\n\n"),
                ResetColor
            )?;
            return Ok(());
        }
    };
    
    // Setup working directory
    let home_dir = env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let work_dir = PathBuf::from(home_dir).join(".hacksor");
    
    // Initialize terminal manager
    let terminal_mgr = TerminalManager::new(work_dir.clone())?;
    
    // Get command monitor
    let command_monitor = terminal_mgr.get_command_monitor();
    
    // Set up output analysis system
    let mut output_rx = command_monitor.get_output_receiver();
    let mut output_analyzer = OutputAnalyzer::new(
        Arc::new(command_monitor.clone()),
        command_monitor.get_output_receiver()
    );
    
    // Set up channels for follow-up actions
    let (action_tx, action_rx) = mpsc::channel(100);
    let (result_tx, mut result_rx) = mpsc::channel(100);
    
    // Set up auto-documentation
    let mut auto_doc = AutoDocumentation::new(
        Arc::new(command_monitor.clone()),
        command_monitor.get_findings_receiver(),
        action_tx.clone(),
        work_dir.clone()
    )?;
    
    // Set up action executor
    let mut action_executor = ActionExecutor::new(
        Arc::new(command_monitor.clone()),
        action_rx,
        result_tx.clone(),
        2 // max concurrent actions
    );
    
    // Security command executor (for direct intent analysis)
    let command_executor = SecurityCommandExecutor::new();
    
    // Start background tasks
    let _output_analyzer_handle = tokio::spawn(async move {
        if let Err(e) = output_analyzer.start().await {
            eprintln!("Output analyzer error: {}", e);
        }
    });
    
    let _auto_doc_handle = tokio::spawn(async move {
        if let Err(e) = auto_doc.start().await {
            eprintln!("Auto-documentation error: {}", e);
        }
    });
    
    let _action_executor_handle = tokio::spawn(async move {
        if let Err(e) = action_executor.start().await {
            eprintln!("Action executor error: {}", e);
        }
    });
    
    // Channel for sending command output from background tasks to main loop
    let (cmd_output_tx, mut cmd_output_rx) = mpsc::channel(100);
    
    // Start task to forward output from command monitor
    let cmd_output_tx_clone = cmd_output_tx.clone();
    tokio::spawn(async move {
        while let Some(output) = output_rx.recv().await {
            if let Err(e) = cmd_output_tx_clone.send(format!("[{}] {}", 
                if output.is_error { "ERROR" } else { "INFO" }, 
                output.line
            )).await {
                eprintln!("Failed to send command output: {}", e);
                break;
            }
        }
    });
    
    // Start task to forward action results
    let cmd_output_tx_clone = cmd_output_tx.clone();
    tokio::spawn(async move {
        while let Some(action) = result_rx.recv().await {
            let status_str = match action.status {
                terminal::ActionStatus::Completed => "COMPLETED",
                terminal::ActionStatus::Failed => "FAILED",
                _ => continue, // Only report completed or failed actions
            };
            
            let action_msg = format!("[ACTION {}] {}", status_str, action.description);
            
            if let Err(e) = cmd_output_tx_clone.send(action_msg).await {
                eprintln!("Failed to send action result: {}", e);
                break;
            }
            
            // If there's a result, send that too (truncated if very long)
            if let Some(result) = action.result {
                let result = if result.len() > 200 {
                    format!("{}... (truncated)", &result[..200])
                } else {
                    result
                };
                
                if let Err(e) = cmd_output_tx_clone.send(format!("[RESULT] {}", result)).await {
                    eprintln!("Failed to send action result: {}", e);
                    break;
                }
            }
        }
    });
    
    // Start conversation loop
    let mut stdout = io::stdout();
    let mut conversation_active = true;
    
    // Get initial response from AI to start the conversation
    match ai.get_response().await {
        Ok(response) => {
            execute!(
                stdout,
                SetForegroundColor(Color::Green),
                Print(format!("[Hacksor] {}\n", response)),
                ResetColor
            )?;
            
            // Add feature hint for users
            execute!(
                stdout,
                SetForegroundColor(Color::Cyan),
                Print("\n[Hacksor Info] I now analyze target profiles (like universities, .edu domains) and automatically use less aggressive scanning by default for prestigious targets. I'll progressively increase scan intensity when you request deeper analysis.\n\n"),
                ResetColor
            )?;
        },
        Err(e) => {
            execute!(
                stdout,
                SetForegroundColor(Color::Red),
                Print(format!("\n[ERROR] Failed to get AI response: {}\n", e)),
                ResetColor
            )?;
            return Ok(());
        }
    }
    
    while conversation_active {
        // This tokio::select will allow us to handle both user input and background output
        tokio::select! {
            // Handle command output from background tasks
            Some(output) = cmd_output_rx.recv() => {
                execute!(
                    stdout,
                    SetForegroundColor(Color::Blue),
                    Print(format!("{}\n", output)),
                    ResetColor
                )?;
                
                // Add the terminal output to the AI context to make it aware of findings
                if output.starts_with("[INFO]") || output.starts_with("[ACTION") || output.starts_with("[RESULT]") {
                    ai.add_assistant_message(&format!("I observed the following in the terminal: {}", output));
                    
                    // Extract command results to help with future queries
                    if output.starts_with("[RESULT]") {
                        // Extract the command ID from previous output if available
                        let mut cmd_id = None;
                        let mut cmd_text = None;
                        
                        // Get the most recently executed command
                        let all_commands = terminal_mgr.get_command_monitor().get_all_commands();
                        if !all_commands.is_empty() {
                            if let Some(latest_cmd) = all_commands.iter()
                                .max_by_key(|cmd| cmd.start_time) {
                                cmd_id = Some(latest_cmd.id.clone());
                                cmd_text = Some(latest_cmd.command.clone());
                            }
                        }
                        
                        // Store the command result
                        if let (Some(cmd), Some(id)) = (cmd_text, cmd_id) {
                            let result_text = output.trim_start_matches("[RESULT] ").to_string();
                            ai.add_command_result(&cmd, &result_text);
                            
                            // Also update the command summary
                            let _ = terminal_mgr.get_command_monitor().update_command_summary(&id, &result_text);
                        }
                    }
                }
                
                // Check if there are more messages in the queue
                // If not, show the prompt
                if cmd_output_rx.try_recv().is_err() {
                    print!("> ");
                    stdout.flush()?;
                }
            }
            
            // Handle user input
            _ = async {
                // Get user input
                print!("> ");
                stdout.flush()?;
                let mut user_input = String::new();
                io::stdin().read_line(&mut user_input)?;
                
                let user_input = user_input.trim();
                
                // Clone ai and terminal_mgr for use in this async block
                let mut ai_clone = ai.clone();
                let terminal_mgr_clone = terminal_mgr.clone();
                
                // Check for exit command
                if user_input.to_lowercase() == "exit" || user_input.to_lowercase() == "quit" {
                    execute!(
                        stdout,
                        SetForegroundColor(Color::Yellow),
                        Print("\n[Hacksor] Session terminated. Goodbye!\n"),
                        ResetColor
                    )?;
                    conversation_active = false;
                    return Ok::<(), anyhow::Error>(());
                }
                
                // Check for abort command to stop running commands
                if user_input.to_lowercase().starts_with("!abort") {
                    let parts: Vec<&str> = user_input.split_whitespace().collect();
                    if parts.len() > 1 {
                        let cmd_id = parts[1];
                        execute!(
                            stdout,
                            SetForegroundColor(Color::Yellow),
                            Print(format!("\n[Hacksor] Attempting to abort command with ID: {}...\n", cmd_id)),
                            ResetColor
                        )?;
                        
                        // Try to terminate the command
                        match terminal_mgr_clone.get_command_monitor().terminate_command(cmd_id).await {
                            Ok(_) => {
                                execute!(
                                    stdout,
                                    SetForegroundColor(Color::Green),
                                    Print(format!("[Hacksor] Successfully terminated command with ID: {}\n", cmd_id)),
                                    ResetColor
                                )?;
                            },
                            Err(e) => {
                                execute!(
                                    stdout,
                                    SetForegroundColor(Color::Red),
                                    Print(format!("[ERROR] Failed to terminate command: {}\n", e)),
                                    ResetColor
                                )?;
                            }
                        }
                        
                        // Don't continue with message processing
                        return Ok::<(), anyhow::Error>(());
                    } else {
                        execute!(
                            stdout,
                            SetForegroundColor(Color::Yellow),
                            Print("\n[Hacksor] Please specify a command ID to abort, e.g., !abort 12345678-1234-1234-1234-123456789abc\n"),
                            ResetColor
                        )?;
                        
                        // List active commands
                        let active_commands = terminal_mgr_clone.get_command_monitor().get_active_commands();
                        if !active_commands.is_empty() {
                            execute!(
                                stdout,
                                SetForegroundColor(Color::Blue),
                                Print("\n[Hacksor] Active commands:\n"),
                                ResetColor
                            )?;
                            
                            for cmd in active_commands {
                                if matches!(cmd.status, CommandStatus::Running) {
                                    execute!(
                                        stdout,
                                        SetForegroundColor(Color::Blue),
                                        Print(format!("ID: {} - Command: {}\n", cmd.id, cmd.command)),
                                        ResetColor
                                    )?;
                                }
                            }
                        } else {
                            execute!(
                                stdout,
                                SetForegroundColor(Color::Blue),
                                Print("\n[Hacksor] No active commands running.\n"),
                                ResetColor
                            )?;
                        }
                        
                        // Don't continue with message processing
                        return Ok::<(), anyhow::Error>(());
                    }
                }
                
                // Handle special command to execute terminal commands directly
                if user_input.to_lowercase().starts_with("!exec") {
                    let command = user_input.trim_start_matches("!exec").trim();
                    
                    // Check if the command would be modified based on target safety
                    let safe_command = apply_target_based_safety(&[command.to_string()])[0].clone();
                    let cmd_modified = command != safe_command;
                    
                    execute!(
                        stdout,
                        SetForegroundColor(Color::Yellow),
                        Print(format!("\n[Hacksor] Executing command and monitoring output...\n")),
                        ResetColor
                    )?;
                    
                    // If the command was modified for safety, show a message
                    if cmd_modified {
                        execute!(
                            stdout,
                            SetForegroundColor(Color::Cyan),
                            Print(format!("[Hacksor] Target appears prestigious - using safer command: {}\n", safe_command)),
                            ResetColor
                        )?;
                    }
                    
                    // Execute with monitoring (using safer version)
                    let safe_command_clone = safe_command.clone();
                    
                    // Execute in a separate task and await completion
                    tokio::spawn(async move {
                        match terminal_mgr_clone.execute_monitored_command(&safe_command_clone, CommandType::Generic).await {
                            Ok(cmd_id) => {
                                let _ = execute!(
                                    io::stdout(),
                                    SetForegroundColor(Color::Blue),
                                    Print(format!("[Hacksor] Monitoring command execution (ID: {})\n", cmd_id)),
                                    ResetColor
                                );
                                
                                // Set a timeout using tokio::time::timeout
                                let wait_result = tokio::time::timeout(
                                    tokio::time::Duration::from_secs(30),
                                    async {
                                        let mut check_interval = tokio::time::interval(tokio::time::Duration::from_millis(500));
                                        loop {
                                            check_interval.tick().await;
                                            if let Some(cmd_status) = terminal_mgr_clone.get_command_monitor().get_command(&cmd_id) {
                                                if !matches!(cmd_status.status, CommandStatus::Running) {
                                                    return true;
                                                }
                                            } else {
                                                return false;
                                            }
                                        }
                                    }
                                ).await;
                                
                                // Check if we timed out or completed
                                let command_completed = match wait_result {
                                    Ok(result) => result,
                                    Err(_) => {
                                        // Timeout occurred
                                        false
                                    }
                                };
                                
                                if !command_completed {
                                    // Timeout reached
                                    let _ = execute!(
                                        io::stdout(),
                                        SetForegroundColor(Color::Yellow),
                                        Print(format!("[Hacksor] Command is taking a long time to complete. You can continue using Hacksor while it finishes.\n")),
                                        ResetColor
                                    );
                                } else {
                                    // Command completed successfully, print a message
                                    let _ = execute!(
                                        io::stdout(),
                                        SetForegroundColor(Color::Green),
                                        Print("\n[Hacksor] Command execution completed. Type your next request.\n> "),
                                        ResetColor
                                    );
                                    let _ = io::stdout().flush();
                                }
                            },
                            Err(e) => {
                                let _ = execute!(
                                    io::stdout(),
                                    SetForegroundColor(Color::Red),
                                    Print(format!("[ERROR] Failed to execute command: {}\n", e)),
                                    ResetColor
                                );
                                
                                // Print the prompt
                                let _ = execute!(
                                    io::stdout(),
                                    Print("\n> "),
                                    ResetColor
                                );
                                let _ = io::stdout().flush();
                            }
                        }
                    });
                    
                    // Don't show the prompt right away
                    return Ok::<(), anyhow::Error>(());
                } 
                
                // First, analyze the user message for security testing intent
                if let Some((command_name, params)) = ai_clone.analyze_user_intent(user_input) {
                    // We detected an intent that maps to a specific security command
                    execute!(
                        stdout,
                        SetForegroundColor(Color::Yellow),
                        Print(format!("\n[Hacksor] I'll run that security test for you right away.\n")),
                        ResetColor
                    )?;
                    
                    // Get the command string
                    let cmd = command_executor.get_command(&command_name)
                        .map(|cmd_template| {
                            let mut cmd_str = cmd_template.template.clone();
                            for (key, value) in &params {
                                cmd_str = cmd_str.replace(&format!("{{{}}}", key), value);
                            }
                            cmd_str
                        })
                        .unwrap_or_else(|| format!("{} {:?}", command_name, params));
                    
                    // Execute the command in a background task and wait for results
                    let cmd_clone = cmd.clone();
                    
                    tokio::spawn(async move {
                        // Determine command type
                        let cmd_type = determine_command_type(&cmd_clone);
                        
                        // Execute with monitoring
                        match terminal_mgr_clone.execute_monitored_command(&cmd_clone, cmd_type).await {
                            Ok(cmd_id) => {
                                let _ = execute!(
                                    io::stdout(),
                                    SetForegroundColor(Color::Blue),
                                    Print(format!("[Hacksor] Monitoring command execution (ID: {})\n", cmd_id)),
                                    ResetColor
                                );
                                
                                // Set a timeout using tokio::time::timeout
                                let wait_result = tokio::time::timeout(
                                    tokio::time::Duration::from_secs(30),
                                    async {
                                        let mut check_interval = tokio::time::interval(tokio::time::Duration::from_millis(500));
                                        loop {
                                            check_interval.tick().await;
                                            if let Some(cmd_status) = terminal_mgr_clone.get_command_monitor().get_command(&cmd_id) {
                                                if !matches!(cmd_status.status, CommandStatus::Running) {
                                                    return true;
                                                }
                                            } else {
                                                return false;
                                            }
                                        }
                                    }
                                ).await;
                                
                                // Check if we timed out or completed
                                let command_completed = match wait_result {
                                    Ok(result) => result,
                                    Err(_) => {
                                        // Timeout occurred
                                        false
                                    }
                                };
                                
                                if !command_completed {
                                    // Timeout reached
                                    let _ = execute!(
                                        io::stdout(),
                                        SetForegroundColor(Color::Yellow),
                                        Print(format!("[Hacksor] Command is taking a long time to complete. You can continue using Hacksor while it finishes.\n")),
                                        ResetColor
                                    );
                                } else {
                                    // Command completed successfully, print a message
                                    let _ = execute!(
                                        io::stdout(),
                                        SetForegroundColor(Color::Green),
                                        Print("\n[Hacksor] Command execution completed. Type your next request.\n> "),
                                        ResetColor
                                    );
                                    let _ = io::stdout().flush();
                                }
                            },
                            Err(e) => {
                                let _ = execute!(
                                    io::stdout(),
                                    SetForegroundColor(Color::Red),
                                    Print(format!("[ERROR] Failed to execute command: {}\n", e)),
                                    ResetColor
                                );
                                
                                // Print the prompt
                                let _ = execute!(
                                    io::stdout(),
                                    Print("\n> "),
                                    ResetColor
                                );
                                let _ = io::stdout().flush();
                            }
                        }
                    });
                    
                    // Add the command execution to AI context
                    ai_clone.add_assistant_message(&format!("I'm running the command: {} and will monitor the results.", cmd));
                    
                    // Don't show the prompt right away
                    return Ok::<(), anyhow::Error>(());
                }
                
                // Add user message to conversation
                ai_clone.add_user_message(user_input);
                
                // Check if user is asking about previous command results
                if ai_clone.is_asking_about_results(user_input) {
                    // Prepare a response about the most recent command results
                    let mut result_response = String::from("Based on the previous commands, ");
                    
                    // Get all completed commands
                    let recent_commands = terminal_mgr_clone.get_command_monitor().get_all_commands();
                    let completed_commands: Vec<_> = recent_commands.iter()
                        .filter(|cmd| !matches!(cmd.status, CommandStatus::Running))
                        .collect();
                    
                    if !completed_commands.is_empty() {
                        // Sort by end time to get the most recent commands first
                        let mut sorted_commands = completed_commands.clone();
                        sorted_commands.sort_by(|a, b| {
                            let a_time = a.end_time.unwrap_or(a.start_time);
                            let b_time = b.end_time.unwrap_or(b.start_time);
                            b_time.cmp(&a_time) // Descending order (most recent first)
                        });
                        
                        for (i, cmd) in sorted_commands.iter().take(3).enumerate() {
                            // Try to read output file to get results
                            if let Ok(output) = std::fs::read_to_string(&cmd.output_file) {
                                // Extract important parts of the output
                                let important_lines: Vec<&str> = output.lines()
                                    .filter(|line| 
                                        !line.trim().is_empty() && 
                                        !line.contains("[STDOUT]") && 
                                        !line.contains("[STDERR]") &&
                                        !line.contains("Press Enter to continue")
                                    )
                                    .take(10) // Limit to 10 lines
                                    .collect();
                                
                                if !important_lines.is_empty() {
                                    let output_summary = important_lines.join("\n");
                                    result_response.push_str(&format!(
                                        "{}I executed `{}` and found: \n{}\n\n", 
                                        if i > 0 { "Additionally, " } else { "" },
                                        cmd.command,
                                        output_summary
                                    ));
                                } else {
                                    result_response.push_str(&format!(
                                        "{}I executed `{}` but no significant output was captured.\n", 
                                        if i > 0 { "Additionally, " } else { "" },
                                        cmd.command
                                    ));
                                }
                            } else {
                                result_response.push_str(&format!(
                                    "{}I executed `{}` but couldn't retrieve the results.\n", 
                                    if i > 0 { "Additionally, " } else { "" },
                                    cmd.command
                                ));
                            }
                        }
                    } else {
                        result_response.push_str("I haven't completed any commands yet. Would you like me to run a specific scan or test?");
                    }
                    
                    // Display the response about results
                    execute!(
                        stdout,
                        SetForegroundColor(Color::Green),
                        Print(format!("[Hacksor] {}\n", result_response)),
                        ResetColor
                    )?;
                    
                    // Add this explanation to AI context
                    ai_clone.add_assistant_message(&result_response);
                    
                    return Ok::<(), anyhow::Error>(());
                }
                
                // Get AI response
                match ai_clone.get_response().await {
                    Ok(response) => {
                        // Process AI response to extract commands
                        let (display_response, commands) = process_response(&response);
                        
                        // Display the response
                        execute!(
                            stdout,
                            SetForegroundColor(Color::Green),
                            Print(format!("[Hacksor] {}\n", display_response)),
                            ResetColor
                        )?;
                        
                        // Execute commands sequentially (not all at once)
                        if !commands.is_empty() {
                            execute!(
                                stdout,
                                SetForegroundColor(Color::Blue),
                                Print(format!("\n[Hacksor] I'm going to execute {} commands. Each will be executed after the previous completes.\n\n", commands.len())),
                                ResetColor
                            )?;
                            
                            // Track if we're in a command execution sequence
                            let command_execution_active = true;
                            
                            // Set a flag in a global context to indicate active command execution
                            let command_execution_context = Arc::new(Mutex::new(command_execution_active));
                            let context_clone = command_execution_context.clone();
                            
                            // Spawn a background task to execute commands sequentially
                            tokio::spawn(async move {
                                for (i, cmd) in commands.iter().enumerate() {
                                    // Notify that we're starting this command
                                    let _ = execute!(
                                        io::stdout(),
                                        SetForegroundColor(Color::Blue),
                                        Print(format!("[Hacksor] Taking action: {}\n", cmd)),
                                        ResetColor
                                    );
                                    
                                    // Execute with monitoring
                                    match terminal_mgr_clone.execute_monitored_command(cmd, determine_command_type(cmd)).await {
                                        Ok(cmd_id) => {
                                            // Add the execution information to the AI context
                                            ai_clone.add_assistant_message(&format!(
                                                "I executed command: {} (execution ID: {})", 
                                                cmd, cmd_id
                                            ));
                                            
                                            // Set a timeout using tokio::time::timeout
                                            let wait_result = tokio::time::timeout(
                                                tokio::time::Duration::from_secs(30),
                                                async {
                                                    let mut check_interval = tokio::time::interval(tokio::time::Duration::from_millis(500));
                                                    loop {
                                                        check_interval.tick().await;
                                                        if let Some(cmd_status) = terminal_mgr_clone.get_command_monitor().get_command(&cmd_id) {
                                                            if !matches!(cmd_status.status, CommandStatus::Running) {
                                                                return true;
                                                            }
                                                        } else {
                                                            return false;
                                                        }
                                                    }
                                                }
                                            ).await;
                                            
                                            // Check if we timed out or completed
                                            let command_completed = match wait_result {
                                                Ok(result) => result,
                                                Err(_) => {
                                                    // Timeout occurred
                                                    false
                                                }
                                            };
                                            
                                            if !command_completed {
                                                // Timeout reached, continue with next command
                                                let _ = execute!(
                                                    io::stdout(),
                                                    SetForegroundColor(Color::Yellow),
                                                    Print(format!("[Hacksor] Command is taking a long time to complete, continuing with next steps...\n")),
                                                    ResetColor
                                                );
                                            }
                                            
                                            // Wait before executing the next command
                                            if i < commands.len() - 1 {
                                                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                                            }
                                        },
                                        Err(e) => {
                                            // Notify the user of the error
                                            let _ = execute!(
                                                io::stdout(),
                                                SetForegroundColor(Color::Red),
                                                Print(format!("[ERROR] Failed to execute command '{}': {}\n", cmd, e)),
                                                ResetColor
                                            );
                                            
                                            // Add the error to the AI context
                                            ai_clone.add_assistant_message(&format!(
                                                "I tried to execute command: {} but encountered error: {}", 
                                                cmd, e
                                            ));
                                        }
                                    }
                                }
                                
                                // All commands executed, mark as complete
                                if let Ok(mut active) = context_clone.lock() {
                                    *active = false;
                                }
                                
                                // Get and analyze the results of completed commands
                                let mut result_analysis = String::new();
                                
                                for (i, cmd) in commands.iter().enumerate() {
                                    // Find the command ID from active commands
                                    let cmd_records = terminal_mgr_clone.get_command_monitor().get_all_commands();
                                    let cmd_record = cmd_records.iter()
                                        .filter(|record| record.command.contains(cmd))
                                        .max_by_key(|record| record.start_time);
                                    
                                    if let Some(record) = cmd_record {
                                        // Try to read the output file
                                        if let Ok(output) = std::fs::read_to_string(&record.output_file) {
                                            // Filter and extract meaningful lines (not just status messages)
                                            let important_lines: Vec<&str> = output.lines()
                                                .filter(|line| 
                                                    !line.trim().is_empty() && 
                                                    !line.contains("[STDOUT]") && 
                                                    !line.contains("[STDERR]") &&
                                                    !line.starts_with("===") &&
                                                    !line.contains("Press Enter to continue")
                                                )
                                                .take(15) // Limit to 15 lines
                                                .collect();
                                            
                                            if !important_lines.is_empty() {
                                                // Add to the result analysis
                                                let cmd_output = important_lines.join("\n");
                                                let analysis = analyze_command_output(cmd, &cmd_output);
                                                
                                                result_analysis.push_str(&format!(
                                                    "{}Command: {}\nResults: {}\n\n", 
                                                    if i > 0 { "\n" } else { "" },
                                                    cmd,
                                                    analysis
                                                ));
                                                
                                                // Add this to AI context for future reference
                                                ai_clone.add_command_result(cmd, &analysis);
                                            } else {
                                                result_analysis.push_str(&format!(
                                                    "{}Command: {}\nNo significant output captured.\n", 
                                                    if i > 0 { "\n" } else { "" },
                                                    cmd
                                                ));
                                            }
                                        }
                                    }
                                }
                                
                                // Final message after all commands complete with results analysis
                                let completion_message = if !result_analysis.is_empty() {
                                    format!("\n[Hacksor] Recon operations completed. Here's what I found:\n\n{}\n\nType your next request for additional actions.\n> ", result_analysis)
                                } else {
                                    "\n[Hacksor] Recon operations completed. Type your next request for additional actions.\n> ".to_string()
                                };
                                
                                let _ = execute!(
                                    io::stdout(),
                                    SetForegroundColor(Color::Green),
                                    Print(completion_message),
                                    ResetColor
                                );
                                let _ = io::stdout().flush();
                            });
                            
                            // Don't show the prompt right after - it will be shown when commands finish
                            return Ok::<(), anyhow::Error>(());
                        }
                    },
                    Err(e) => {
                        execute!(
                            stdout,
                            SetForegroundColor(Color::Red),
                            Print(format!("\n[ERROR] Failed to get AI response: {}\n", e)),
                            ResetColor
                        )?;
                    }
                }
                
                Ok::<(), anyhow::Error>(())
            } => {}
        }
    }

    Ok(())
}

// Process the AI response to extract both the display text and autonomous commands
fn process_response(response: &str) -> (String, Vec<String>) {
    // Extract commands from code blocks - this is the most reliable method
    let mut commands = extract_commands(response);
    
    // Look for special action markers in the response
    // These are markers that Hacksor would use to indicate it's taking action
    for line in response.lines() {
        if line.trim().starts_with("[Hacksor] Taking action:") {
            let action_parts = line.trim().split("Taking action:").collect::<Vec<&str>>();
            if action_parts.len() > 1 {
                let action_cmd = action_parts[1].trim();
                
                // Extract command from backticks if present
                let clean_cmd = if action_cmd.contains('`') && action_cmd.matches('`').count() >= 2 {
                    // Extract command between backticks
                    let parts: Vec<&str> = action_cmd.split('`').collect();
                    if parts.len() >= 3 {
                        parts[1].trim()
                    } else {
                        action_cmd.trim_matches(|c| c == '`' || c == '.' || c == ',' || c == ')')
                    }
                } else {
                    // No backticks, just clean up the command
                    action_cmd.trim_matches(|c| c == '`' || c == '.' || c == ',' || c == ')')
                };
                
                if !clean_cmd.is_empty() && !commands.contains(&clean_cmd.to_string()) {
                    commands.push(clean_cmd.to_string());
                }
            }
        }
    }
    
    // Final clean-up pass for all commands
    let cleaned_commands: Vec<String> = commands.iter()
        .map(|cmd| {
            cmd.trim_matches(|c| c == '`' || c == '.' || c == ',' || c == ')')
               .to_string()
        })
        .filter(|cmd| {
            // Filter out explanatory text that contains tool names but isn't a command
            let explanatory_phrases = [
                "try this", "this will", "command:", "run this", "executing:",
                "scan just", "lay of the land", "scan finishes", "tell me what", 
                "we can", "you can", "let's", "while that's", "once the", 
                "get a", "gives us", "let me know", "execute this"
            ];
            
            // Reject commands that contain explanatory phrases
            !explanatory_phrases.iter().any(|phrase| cmd.to_lowercase().contains(phrase))
        })
        .collect();
    
    // Apply safety modifications to commands based on target
    let cleaned_commands = apply_target_based_safety(&cleaned_commands);
    
    // Sanitize the response - remove action markers for display
    let display_response = response
        .lines()
        .filter(|line| !line.trim().starts_with("[ACTION]"))
        .collect::<Vec<&str>>()
        .join("\n");
    
    (display_response, cleaned_commands)
}

// Apply safety modifications to commands based on target domain
fn apply_target_based_safety(commands: &[String]) -> Vec<String> {
    let prestigious_domains = [
        "edu", "gov", "mil", "harvard", "stanford", "mit", "yale", 
        "princeton", "columbia", "cornell", "dartmouth", "brown", "upenn",
        "berkeley", "ucla", "usc", "duke", "jhu", "nih", "nasa", "noaa", "usgs"
    ];
    
    commands.iter().map(|cmd| {
        let mut modified_cmd = cmd.clone();
        
        // Check if command targets a prestigious domain
        let targets_prestigious = prestigious_domains.iter()
            .any(|domain| cmd.contains(domain));
            
        if targets_prestigious {
            // Modify nmap commands to be less aggressive
            if cmd.starts_with("nmap") {
                // Remove -T4, -T5 aggressive timing and replace with -T2
                if cmd.contains(" -T4") || cmd.contains(" -T5") {
                    modified_cmd = modified_cmd.replace(" -T4", " -T2").replace(" -T5", " -T2");
                }
                
                // If no timing specified, add -T2
                if !modified_cmd.contains(" -T") {
                    modified_cmd = format!("{} -T2", modified_cmd);
                }
                
                // Replace -A with more targeted flags if present
                if modified_cmd.contains(" -A") {
                    modified_cmd = modified_cmd.replace(" -A", " -sV");
                }
            }
            
            // Reduce threads for directory brute forcing
            if cmd.starts_with("gobuster") || cmd.contains("ffuf") || cmd.contains("dirsearch") {
                // Replace high thread counts with lower ones
                let re = regex::Regex::new(r" -t (\d+)").unwrap();
                if let Some(caps) = re.captures(&modified_cmd) {
                    if let Some(thread_match) = caps.get(1) {
                        if let Ok(thread_count) = thread_match.as_str().parse::<i32>() {
                            if thread_count > 10 {
                                modified_cmd = re.replace(&modified_cmd, " -t 10").to_string();
                            }
                        }
                    }
                }
                
                // If no thread specified, add a conservative one
                if !modified_cmd.contains(" -t ") {
                    modified_cmd = format!("{} -t 10", modified_cmd);
                }
            }
        }
        
        modified_cmd
    }).collect()
}

fn setup_terminal() -> Result<()> {
    // Clear screen
    let mut stdout = io::stdout();
    execute!(stdout, Clear(ClearType::All), MoveTo(0, 0))?;
    
    Ok(())
}

fn display_hacksor_welcome() -> Result<()> {
    let mut stdout = io::stdout();
    
    // ASCII art banner
    let banner = r"
    ██╗  ██╗ █████╗  ██████╗██╗  ██╗███████╗ ██████╗ ██████╗ 
    ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔═══██╗██╔══██╗
    ███████║███████║██║     █████╔╝ ███████╗██║   ██║██████╔╝
    ██╔══██║██╔══██║██║     ██╔═██╗ ╚════██║██║   ██║██╔══██╗
    ██║  ██║██║  ██║╚██████╗██║  ██╗███████║╚██████╔╝██║  ██║
    ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝
                                                           
    ";
    
    execute!(
        stdout,
        SetForegroundColor(Color::Red),
        Print(banner),
        ResetColor,
        Print("\n   [Powered by Gemini 1.5 Pro]\n\n")
    )?;
    
    Ok(())
}

fn extract_commands(text: &str) -> Vec<String> {
    let mut commands = Vec::new();
    let mut in_code_block = false;
    let mut code_block_type = "";
    let mut current_command = String::new();
    
    for line in text.lines() {
        if line.trim().starts_with("```") {
            if in_code_block {
                // End of code block
                in_code_block = false;
                if !current_command.trim().is_empty() && 
                   (code_block_type == "bash" || code_block_type == "sh" || code_block_type == "shell") {
                    // Process multi-line commands
                    for cmd_line in current_command.lines() {
                        let trimmed = cmd_line.trim();
                        // Skip empty lines and comment lines
                        if !trimmed.is_empty() && !trimmed.starts_with("#") {
                            // Check for explanatory text within code blocks
                            let explanatory_phrases = [
                                "try this", "this will", "command:", "run this", "executing:",
                                "scan just", "lay of the land", "scan finishes", "tell me what", 
                                "we can", "you can", "let's", "while that's", "once the", 
                                "get a", "gives us", "let me know", "execute this", "we'll",
                                "you'll", "finished", "finishes", "look for", "find out"
                            ];
                            
                            let is_explanatory = explanatory_phrases.iter()
                                .any(|phrase| trimmed.to_lowercase().contains(phrase));
                                
                            if !is_explanatory {
                                // Clean up the command before adding it
                                let clean_command = trimmed
                                    .trim_matches(|c| c == '`' || c == '.' || c == ',' || c == ')')
                                    .to_string();
                                    
                                if !clean_command.is_empty() {
                                    // Validate the command structure for nmap
                                    if (clean_command.starts_with("nmap") || clean_command.starts_with("sudo nmap")) &&
                                       !(clean_command.contains(".com") || clean_command.contains(".net") || 
                                         clean_command.contains(".org") || clean_command.contains(".edu") || 
                                         clean_command.contains(".gov") || clean_command.contains(".io") || 
                                         clean_command.contains(".co") || clean_command.contains(" localhost") || 
                                         clean_command.contains(" 127.0.0.1") || clean_command.contains(" 10.") || 
                                         clean_command.contains(" 192.168.") || clean_command.contains(" 172.")) {
                                        // Skip commands that look like nmap but don't have a valid target
                                        continue;
                                    }
                                    
                                    commands.push(clean_command);
                                }
                            }
                        }
                    }
                }
                current_command = String::new();
            } else {
                // Start of code block
                in_code_block = true;
                code_block_type = line.trim().trim_start_matches("```").trim();
                current_command = String::new();
            }
        } else if in_code_block && 
                  (code_block_type == "bash" || code_block_type == "sh" || code_block_type == "shell") {
            current_command.push_str(line);
            current_command.push('\n');
        }
    }
    
    commands
}

async fn execute_command(command: &str) -> Result<()> {
    let mut stdout = io::stdout();
    
    // Launch in a new terminal window with error handling
    let terminal_cmd = format!(
        "x-terminal-emulator -e 'bash -c \"echo [Hacksor] Executing: {} && {} || echo [ERROR] Command failed with error code $?; echo Press Enter to close...; read\"'",
        command, command
    );
    
    match Command::new("bash")
        .arg("-c")
        .arg(&terminal_cmd)
        .spawn() {
            Ok(_) => {
                // Wait a moment for the terminal to open
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                
                execute!(
                    stdout,
                    SetForegroundColor(Color::Blue),
                    Print("\n[Hacksor] Command executed in a new terminal.\n"),
                    ResetColor
                )?;
            },
            Err(e) => {
                execute!(
                    stdout,
                    SetForegroundColor(Color::Red),
                    Print(format!("\n[ERROR] Failed to execute command: {}\n", e)),
                    ResetColor
                )?;
            }
        }
    
    Ok(())
}

/// Determine the command type based on the command string
fn determine_command_type(command: &str) -> CommandType {
    let command = command.to_lowercase();
    
    if command.contains("nmap") || command.contains("ping") || command.contains("dig") || 
       command.contains("whois") || command.contains("traceroute") || command.contains("host") ||
       command.contains("subfinder") || command.contains("amass") || command.contains("assetfinder") {
        CommandType::Reconnaissance
    } else if command.contains("gobuster") || command.contains("dirsearch") || command.contains("nikto") || 
              command.contains("wfuzz") || command.contains("ffuf") || command.contains("dirb") {
        CommandType::Scanning
    } else if command.contains("sqlmap") || command.contains("metasploit") || command.contains("msfconsole") ||
              command.contains("exploitdb") || command.contains("searchsploit") {
        CommandType::Exploitation
    } else if command.contains("nuclei") || command.contains("nessus") || command.contains("openvas") ||
              command.contains("zap") || command.contains("burpsuite") {
        CommandType::Vulnerability
    } else if command.contains("echo") || command.contains("cat") || command.contains("grep") || 
              command.contains("find") || command.contains("awk") || command.contains("sed") {
        CommandType::Documentation
    } else {
        CommandType::Generic
    }
}

/// Analyze command output to provide meaningful interpretation
fn analyze_command_output(command: &str, output: &str) -> String {
    // Different analysis based on command type
    let command_lower = command.to_lowercase();
    
    // WAF detection commands
    if command_lower.contains("waf") || command_lower.contains("wafw00f") {
        if output.is_empty() || output.contains("No WAF detected") {
            "No WAF (Web Application Firewall) was detected. This suggests the site may not have this layer of protection.".to_string()
        } else if output.contains("detected") || output.contains("Detected:") || output.contains("identified") {
            // Extract the WAF information
            let waf_line = output.lines()
                .find(|line| line.contains("detected") || line.contains("identified") || line.contains("Detected:"))
                .unwrap_or("A WAF was detected but could not extract details.");
            
            format!("A WAF was detected! {}", waf_line)
        } else {
            format!("Ran WAF detection. Raw output:\n{}", output)
        }
    }
    // NMAP command analysis
    else if command_lower.contains("nmap") {
        if output.contains("open") {
            // Extract open ports
            let open_port_lines: Vec<&str> = output.lines()
                .filter(|line| line.contains("open"))
                .collect();
            
            if !open_port_lines.is_empty() {
                format!("Found open ports:\n{}", open_port_lines.join("\n"))
            } else {
                "Scan completed but couldn't extract open port details.".to_string()
            }
        } else if output.contains("closed") || output.contains("filtered") {
            "No open ports were detected in the specified range.".to_string()
        } else {
            format!("Scan completed. Raw output:\n{}", output)
        }
    }
    // DNS information commands
    else if command_lower.contains("dig") || command_lower.contains("host") || command_lower.contains("nslookup") {
        if output.contains("ANSWER SECTION") || output.contains("has address") {
            let dns_info = output.lines()
                .filter(|line| 
                    line.contains("IN") || 
                    line.contains("has address") || 
                    line.contains("nameserver") ||
                    line.contains("mail is handled")
                )
                .collect::<Vec<&str>>()
                .join("\n");
            
            format!("DNS information retrieved:\n{}", dns_info)
        } else {
            format!("DNS lookup completed. Raw output:\n{}", output)
        }
    }
    // Directory/file enumeration commands
    else if command_lower.contains("gobuster") || command_lower.contains("dirb") || command_lower.contains("dirsearch") {
        if output.contains("Status:") || output.contains("found") || output.contains("Result") {
            // Extract found directories/files
            let findings = output.lines()
                .filter(|line| 
                    line.contains("Status: 200") || 
                    line.contains("Status: 301") || 
                    line.contains("Status: 302") ||
                    line.contains("(Status: 200)") ||
                    line.contains("(Status: 301)") ||
                    line.contains("(Status: 302)")
                )
                .collect::<Vec<&str>>()
                .join("\n");
            
            if !findings.is_empty() {
                format!("Found directories/files:\n{}", findings)
            } else {
                "Directory scan completed but no significant findings were detected.".to_string()
            }
        } else {
            "Directory scan completed but no accessible resources were found.".to_string()
        }
    }
    // CURL command analysis
    else if command_lower.contains("curl") {
        if command_lower.contains("server") {
            // Extract server header information
            let server_info = output.lines()
                .find(|line| line.contains("Server:"))
                .unwrap_or("No Server header found.");
            
            format!("Server information: {}", server_info)
        } else if output.contains("<html") || output.contains("<!DOCTYPE") {
            "Retrieved HTML content from the target site.".to_string()
        } else if output.contains("{") && output.contains("}") {
            "Retrieved JSON data from the target site.".to_string()
        } else {
            format!("CURL command completed. Output:\n{}", output)
        }
    }
    // Default analysis
    else {
        format!("Command completed. Output:\n{}", output)
    }
}
