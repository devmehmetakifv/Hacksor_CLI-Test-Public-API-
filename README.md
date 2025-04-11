# Hacksor

An advanced AI-driven penetration testing assistant that autonomously executes security testing commands based on user intent.

## Features

- **Autonomous Command Execution**: Hacksor analyzes user messages to detect security testing intents and automatically executes relevant commands.
- **Intent-Driven Security Testing**: Natural language processing capabilities extract security testing intents from casual conversation.
- **Domain-Specific Command Templates**: Pre-configured security testing tools and commands for common scenarios.
- **Smart Command Selection**: Automatically chooses the right security testing tool based on user's needs.
- **Parallel Command Execution**: Runs commands in separate terminals to maintain interactive conversation.

## Supported Security Testing Capabilities

- XSS vulnerability scanning (xsser, dalfox)
- Port scanning (nmap with various options)
- Directory enumeration (dirsearch)
- Subdomain discovery (sublist3r)
- Web vulnerability assessment (nikto)
- And more...

## Usage Examples

Simply chat with Hacksor in natural language, and it will detect when you want to perform security testing:

```
> Let's check for XSS vulnerabilities on example.com

[Hacksor] I'll run that security test for you right away.
[Hacksor] Executed: xsser --url example.com
```

```
> Can you scan the ports on test.example.org?

[Hacksor] I'll run that security test for you right away.
[Hacksor] Executed: nmap test.example.org
```

## How It Works

Hacksor uses a sophisticated intent detection system:

1. **Intent Analysis**: Parses user messages to identify security testing intents.
2. **Command Mapping**: Maps detected intents to appropriate security tools.
3. **Parameter Extraction**: Automatically extracts target domains and other parameters.
4. **Command Execution**: Runs security commands in separate terminals.
5. **Contextual Response**: Provides helpful guidance while tools are running.

## Architecture

Hacksor's architecture consists of several key components:

- **AI Module**: Interfaces with Gemini 1.5 Pro for natural language understanding.
- **Intent Detector**: Identifies security testing intents from user messages.
- **Security Command Executor**: Maintains a registry of security tools and executes them.
- **Terminal Manager**: Manages command execution in separate terminal windows.

## Environment Setup

To run Hacksor, you'll need:

```
export GEMINI_API_KEY="your-api-key"
```

## Building and Running

```
cargo build
cargo run
```

## Requirements

- Rust (latest stable)
- Common security testing tools installed on your system (nmap, xsser, etc.)
- Gemini API key

## Configuration

Create a `config.toml` file in your working directory:

```toml
api_key = "your-api-key"
working_dir = "sessions"

[[tools]]
name = "nmap"
path = "/usr/bin/nmap"
args = ["-sV", "-sC"]

[rate_limit]
requests_per_minute = 60
concurrent_connections = 10
```

## Scope File Format

The scope file should contain one target per line. Lines starting with # are treated as comments.

```
# Main domain
example.com
*.example.com
api.example.com
```

## License

Proprietary - All rights reserved 