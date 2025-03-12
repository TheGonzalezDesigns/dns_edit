use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::Command as ProcessCommand;
use std::str::FromStr;
use thiserror::Error;

// Constants
const HOSTS_FILE: &str = "/etc/hosts";
const BACKUP_DIR: &str = "/usr/local/dns";

#[derive(Debug, Error)]
enum DnsEditError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    
    #[error("Failed to parse hosts file: {0}")]
    ParseError(String),
    
    #[error("Git operation failed: {0}")]
    GitError(String),
    
    #[error("Invalid IP address: {0}")]
    InvalidIp(String),
    
    #[error("Invalid hostname: {0}")]
    InvalidHostname(String),
    
    #[error("DNS corruption detected. Aborting edit.")]
    DnsCorruption,
}

type Result<T> = std::result::Result<T, DnsEditError>;

#[derive(Parser)]
#[command(name = "DNS Edit")]
#[command(author = "DNS Editor")]
#[command(version = "1.0")]
#[command(about = "Edit your DNS by updating /etc/hosts programmatically with version control", long_about = None)]
struct Cli {
    /// Turn on verbose output
    #[arg(short, long)]
    verbose: bool,
    
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List all DNS entries
    List {
        /// Optional filter for hostname pattern
        #[arg(short, long)]
        filter: Option<String>,
    },
    /// Add a new DNS entry
    Add {
        /// IP address (IPv4 or IPv6)
        #[arg(index = 1)]
        ip: String,
        
        /// Hostname to associate with the IP
        #[arg(index = 2)]
        hostname: String,
    },
    /// Remove a DNS entry
    Remove {
        /// Hostname to remove
        #[arg(index = 1)]
        hostname: String,
    },
    /// Update an existing DNS entry
    Update {
        /// Hostname to update
        #[arg(index = 1)]
        hostname: String,
        
        /// New IP address
        #[arg(index = 2)]
        ip: String,
    },
    /// Restore a specific backup
    Restore {
        /// Commit hash to restore (defaults to latest)
        #[arg(short, long)]
        commit: Option<String>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct DnsEntry {
    ip: String,
    hostnames: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DnsFile {
    entries: Vec<DnsEntry>,
    comments: Vec<String>,
}

impl DnsFile {
    fn from_content(content: &str) -> Result<Self> {
        let mut entries = Vec::new();
        let mut comments = Vec::new();
        
        for line in content.lines() {
            let line = line.trim();
            
            if line.is_empty() {
                continue;
            } else if line.starts_with('#') {
                comments.push(line.to_string());
            } else if line.contains(' ') || line.contains('\t') {
                let mut parts = line.split_whitespace();
                if let Some(ip) = parts.next() {
                    // Validate IP
                    if !Self::is_valid_ip(ip) {
                        return Err(DnsEditError::DnsCorruption);
                    }
                    
                    let hostnames: Vec<String> = parts
                        .map(|name| {
                            if !Self::is_valid_hostname(name) {
                                Err(DnsEditError::DnsCorruption)
                            } else {
                                Ok(name.to_string())
                            }
                        })
                        .collect::<Result<Vec<String>>>()?;
                    
                    entries.push(DnsEntry {
                        ip: ip.to_string(),
                        hostnames,
                    });
                } else {
                    return Err(DnsEditError::DnsCorruption);
                }
            } else {
                return Err(DnsEditError::DnsCorruption);
            }
        }
        
        Ok(DnsFile { entries, comments })
    }
    
    fn to_string(&self) -> String {
        let mut result = String::new();
        
        // Add comments
        for comment in &self.comments {
            result.push_str(comment);
            result.push('\n');
        }
        
        // Add entries
        for entry in &self.entries {
            result.push_str(&entry.ip);
            for hostname in &entry.hostnames {
                result.push_str(" ");
                result.push_str(hostname);
            }
            result.push('\n');
        }
        
        result
    }
    
    fn is_valid_ip(ip: &str) -> bool {
        IpAddr::from_str(ip).is_ok()
    }
    
    fn is_valid_hostname(hostname: &str) -> bool {
        // Basic hostname validation
        // RFC 1123 & 952 rules: letters, digits, hyphens, not starting/ending with hyphen
        // More complex validation with regex is possible
        let valid_chars = |c: char| c.is_alphanumeric() || c == '-' || c == '.';
        
        !hostname.is_empty() 
            && hostname.chars().all(valid_chars)
            && !hostname.starts_with('-')
            && !hostname.ends_with('-')
            && hostname.len() <= 253
    }
    
    fn add_entry(&mut self, ip: &str, hostname: &str) -> Result<()> {
        // Validate inputs
        if !Self::is_valid_ip(ip) {
            return Err(DnsEditError::InvalidIp(ip.to_string()));
        }
        
        if !Self::is_valid_hostname(hostname) {
            return Err(DnsEditError::InvalidHostname(hostname.to_string()));
        }
        
        // Check if hostname already exists
        for entry in &mut self.entries {
            if entry.hostnames.contains(&hostname.to_string()) {
                return Err(DnsEditError::ParseError(format!("Hostname {} already exists", hostname)));
            }
        }
        
        // Find if IP already exists
        for entry in &mut self.entries {
            if entry.ip == ip {
                entry.hostnames.push(hostname.to_string());
                return Ok(());
            }
        }
        
        // Create new entry
        self.entries.push(DnsEntry {
            ip: ip.to_string(),
            hostnames: vec![hostname.to_string()],
        });
        
        Ok(())
    }
    
    fn remove_entry(&mut self, hostname: &str) -> Result<()> {
        let mut updated = false;
        
        for entry in &mut self.entries {
            if let Some(pos) = entry.hostnames.iter().position(|h| h == hostname) {
                entry.hostnames.remove(pos);
                updated = true;
                break;
            }
        }
        
        // Remove any empty entries
        self.entries.retain(|entry| !entry.hostnames.is_empty());
        
        if !updated {
            Err(DnsEditError::ParseError(format!("Hostname {} not found", hostname)))
        } else {
            Ok(())
        }
    }
    
    fn update_entry(&mut self, hostname: &str, new_ip: &str) -> Result<()> {
        // Validate IP
        if !Self::is_valid_ip(new_ip) {
            return Err(DnsEditError::InvalidIp(new_ip.to_string()));
        }
        
        // Remove the old entry
        self.remove_entry(hostname)?;
        
        // Add the new entry
        self.add_entry(new_ip, hostname)?;
        
        Ok(())
    }
}

fn init_git_repo() -> Result<()> {
    // Create backup directory if it doesn't exist
    fs::create_dir_all(BACKUP_DIR)
        .map_err(|e| DnsEditError::Io(e))?;
    
    // Check if git repository already exists
    let git_dir = PathBuf::from(BACKUP_DIR).join(".git");
    if !git_dir.exists() {
        // Initialize git repository
        let output = ProcessCommand::new("git")
            .args(["init"])
            .current_dir(BACKUP_DIR)
            .output()
            .map_err(|e| DnsEditError::GitError(format!("Failed to initialize git repo: {}", e)))?;
        
        if !output.status.success() {
            return Err(DnsEditError::GitError(String::from_utf8_lossy(&output.stderr).to_string()));
        }
        
        // Configure git user for commits
        let _ = ProcessCommand::new("git")
            .args(["config", "user.name", "DNS Edit"])
            .current_dir(BACKUP_DIR)
            .output();
            
        let _ = ProcessCommand::new("git")
            .args(["config", "user.email", "dns-edit@localhost"])
            .current_dir(BACKUP_DIR)
            .output();
    }
    
    Ok(())
}

fn backup_hosts_file(message: &str) -> Result<()> {
    // Initialize git repository
    init_git_repo()?;
    
    // Copy current hosts file to backup directory
    let hosts_content = fs::read_to_string(HOSTS_FILE)
        .map_err(|e| DnsEditError::Io(e))?;
    
    let backup_path = PathBuf::from(BACKUP_DIR).join("hosts");
    fs::write(&backup_path, hosts_content)
        .map_err(|e| DnsEditError::Io(e))?;
    
    // Add to git
    let _ = ProcessCommand::new("git")
        .args(["add", "hosts"])
        .current_dir(BACKUP_DIR)
        .output()
        .map_err(|e| DnsEditError::GitError(format!("Failed to add to git: {}", e)))?;
    
    // Commit changes
    let output = ProcessCommand::new("git")
        .args(["commit", "-m", message])
        .current_dir(BACKUP_DIR)
        .output()
        .map_err(|e| DnsEditError::GitError(format!("Failed to commit: {}", e)))?;
    
    if !output.status.success() && !String::from_utf8_lossy(&output.stderr).contains("nothing to commit") {
        return Err(DnsEditError::GitError(String::from_utf8_lossy(&output.stderr).to_string()));
    }
    
    Ok(())
}

fn restore_from_backup(commit: Option<&str>) -> Result<()> {
    // Initialize git repository
    init_git_repo()?;
    
    // Backup current hosts file before restoring
    backup_hosts_file("Auto-backup before restore")?;
    
    // Checkout specific commit or HEAD
    let commit_ref = commit.unwrap_or("HEAD");
    
    let output = ProcessCommand::new("git")
        .args(["checkout", commit_ref, "--", "hosts"])
        .current_dir(BACKUP_DIR)
        .output()
        .map_err(|e| DnsEditError::GitError(format!("Failed to checkout: {}", e)))?;
    
    if !output.status.success() {
        return Err(DnsEditError::GitError(String::from_utf8_lossy(&output.stderr).to_string()));
    }
    
    // Copy restored file back to /etc/hosts
    let backup_path = PathBuf::from(BACKUP_DIR).join("hosts");
    let backup_content = fs::read_to_string(&backup_path)
        .map_err(|e| DnsEditError::Io(e))?;
    
    fs::write(HOSTS_FILE, backup_content)
        .map_err(|e| DnsEditError::Io(e))?;
    
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    
    match &cli.command {
        Commands::List { filter } => {
            let content = fs::read_to_string(HOSTS_FILE)?;
            let dns_file = DnsFile::from_content(&content)?;
            
            println!("DNS Entries:");
            for entry in dns_file.entries {
                for hostname in entry.hostnames {
                    if let Some(pattern) = filter {
                        if !hostname.contains(pattern) {
                            continue;
                        }
                    }
                    println!("{} -> {}", hostname, entry.ip);
                }
            }
        }
        
        Commands::Add { ip, hostname } => {
            // Backup before modification
            backup_hosts_file(&format!("Backup before adding {} -> {}", hostname, ip))?;
            
            // Read and parse hosts file
            let content = fs::read_to_string(HOSTS_FILE)?;
            let mut dns_file = DnsFile::from_content(&content)?;
            
            // Add new entry
            dns_file.add_entry(ip, hostname)?;
            
            // Write back to hosts file
            fs::write(HOSTS_FILE, dns_file.to_string())?;
            
            println!("Added DNS entry: {} -> {}", hostname, ip);
        }
        
        Commands::Remove { hostname } => {
            // Backup before modification
            backup_hosts_file(&format!("Backup before removing {}", hostname))?;
            
            // Read and parse hosts file
            let content = fs::read_to_string(HOSTS_FILE)?;
            let mut dns_file = DnsFile::from_content(&content)?;
            
            // Remove entry
            dns_file.remove_entry(hostname)?;
            
            // Write back to hosts file
            fs::write(HOSTS_FILE, dns_file.to_string())?;
            
            println!("Removed DNS entry for {}", hostname);
        }
        
        Commands::Update { hostname, ip } => {
            // Backup before modification
            backup_hosts_file(&format!("Backup before updating {} to {}", hostname, ip))?;
            
            // Read and parse hosts file
            let content = fs::read_to_string(HOSTS_FILE)?;
            let mut dns_file = DnsFile::from_content(&content)?;
            
            // Update entry
            dns_file.update_entry(hostname, ip)?;
            
            // Write back to hosts file
            fs::write(HOSTS_FILE, dns_file.to_string())?;
            
            println!("Updated DNS entry: {} -> {}", hostname, ip);
        }
        
        Commands::Restore { commit } => {
            restore_from_backup(commit.as_deref())?;
            println!("Restored hosts file from backup{}", 
                     commit.as_ref().map_or(String::new(), |c| format!(" (commit {})", c)));
        }
    }
    
    Ok(())
}
