use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::Command as ProcessCommand;
use std::str::FromStr;
use thiserror::Error;

// Constants with environment variable overrides for testing
fn hosts_file() -> String {
    std::env::var("HOSTS_FILE").unwrap_or_else(|_| "/etc/hosts".to_string())
}

fn backup_dir() -> String {
    std::env::var("BACKUP_DIR").unwrap_or_else(|_| "/usr/local/dns".to_string())
}

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
        
        if hostname.is_empty() || hostname.len() > 253 {
            return false;
        }
        
        // Check each label between dots
        for label in hostname.split('.') {
            if label.is_empty() 
                || label.starts_with('-') 
                || label.ends_with('-') 
                || !label.chars().all(|c| c.is_alphanumeric() || c == '-') {
                return false;
            }
        }
        
        true
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
    let backup_dir_path = backup_dir();
    fs::create_dir_all(&backup_dir_path)
        .map_err(|e| DnsEditError::Io(e))?;
    
    // Check if git repository already exists
    let git_dir = PathBuf::from(&backup_dir_path).join(".git");
    if !git_dir.exists() {
        // Initialize git repository
        let output = ProcessCommand::new("git")
            .args(["init"])
            .current_dir(&backup_dir_path)
            .output()
            .map_err(|e| DnsEditError::GitError(format!("Failed to initialize git repo: {}", e)))?;
        
        if !output.status.success() {
            return Err(DnsEditError::GitError(String::from_utf8_lossy(&output.stderr).to_string()));
        }
        
        // Configure git user for commits
        let _ = ProcessCommand::new("git")
            .args(["config", "user.name", "DNS Edit"])
            .current_dir(&backup_dir_path)
            .output();
            
        let _ = ProcessCommand::new("git")
            .args(["config", "user.email", "dns-edit@localhost"])
            .current_dir(&backup_dir_path)
            .output();
    }
    
    Ok(())
}

fn backup_hosts_file(message: &str) -> Result<()> {
    // Initialize git repository
    init_git_repo()?;
    
    // Copy current hosts file to backup directory
    let hosts_file_path = hosts_file();
    let backup_dir_path = backup_dir();
    
    let hosts_content = fs::read_to_string(&hosts_file_path)
        .map_err(|e| DnsEditError::Io(e))?;
    
    let backup_path = PathBuf::from(&backup_dir_path).join("hosts");
    fs::write(&backup_path, hosts_content)
        .map_err(|e| DnsEditError::Io(e))?;
    
    // Add to git
    let _ = ProcessCommand::new("git")
        .args(["add", "hosts"])
        .current_dir(&backup_dir_path)
        .output()
        .map_err(|e| DnsEditError::GitError(format!("Failed to add to git: {}", e)))?;
    
    // Commit changes
    let output = ProcessCommand::new("git")
        .args(["commit", "-m", message])
        .current_dir(&backup_dir_path)
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
    let backup_dir_path = backup_dir();
    let hosts_file_path = hosts_file();
    
    let output = ProcessCommand::new("git")
        .args(["checkout", commit_ref, "--", "hosts"])
        .current_dir(&backup_dir_path)
        .output()
        .map_err(|e| DnsEditError::GitError(format!("Failed to checkout: {}", e)))?;
    
    if !output.status.success() {
        return Err(DnsEditError::GitError(String::from_utf8_lossy(&output.stderr).to_string()));
    }
    
    // Copy restored file back to hosts file
    let backup_path = PathBuf::from(&backup_dir_path).join("hosts");
    let backup_content = fs::read_to_string(&backup_path)
        .map_err(|e| DnsEditError::Io(e))?;
    
    fs::write(&hosts_file_path, backup_content)
        .map_err(|e| DnsEditError::Io(e))?;
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_is_valid_ip() {
        // Valid IPs
        assert!(DnsFile::is_valid_ip("127.0.0.1"));
        assert!(DnsFile::is_valid_ip("192.168.1.1"));
        assert!(DnsFile::is_valid_ip("::1"));
        assert!(DnsFile::is_valid_ip("2001:db8::1"));
        
        // Invalid IPs
        assert!(!DnsFile::is_valid_ip("256.0.0.1"));
        assert!(!DnsFile::is_valid_ip("127.0.0"));
        assert!(!DnsFile::is_valid_ip("hello"));
        assert!(!DnsFile::is_valid_ip(""));
    }
    
    #[test]
    fn test_is_valid_hostname() {
        // Valid hostnames
        assert!(DnsFile::is_valid_hostname("localhost"));
        assert!(DnsFile::is_valid_hostname("example.com"));
        assert!(DnsFile::is_valid_hostname("sub-domain.example.com"));
        assert!(DnsFile::is_valid_hostname("test123.local"));
        
        // Invalid hostnames
        assert!(!DnsFile::is_valid_hostname("-invalid.com"));
        assert!(!DnsFile::is_valid_hostname("invalid-.com"));
        assert!(!DnsFile::is_valid_hostname("invalid$char.com"));
        assert!(!DnsFile::is_valid_hostname(""));
    }
    
    #[test]
    fn test_parse_hosts_file() {
        let content = "# This is a comment
127.0.0.1 localhost
::1 localhost ip6-localhost ip6-loopback
192.168.1.100 test.local
";
        let dns_file = DnsFile::from_content(content).unwrap();
        
        assert_eq!(dns_file.comments.len(), 1);
        assert_eq!(dns_file.comments[0], "# This is a comment");
        
        assert_eq!(dns_file.entries.len(), 3);
        
        // Check first entry
        assert_eq!(dns_file.entries[0].ip, "127.0.0.1");
        assert_eq!(dns_file.entries[0].hostnames.len(), 1);
        assert_eq!(dns_file.entries[0].hostnames[0], "localhost");
        
        // Check second entry
        assert_eq!(dns_file.entries[1].ip, "::1");
        assert_eq!(dns_file.entries[1].hostnames.len(), 3);
        assert_eq!(dns_file.entries[1].hostnames[0], "localhost");
        assert_eq!(dns_file.entries[1].hostnames[1], "ip6-localhost");
        assert_eq!(dns_file.entries[1].hostnames[2], "ip6-loopback");
        
        // Check third entry
        assert_eq!(dns_file.entries[2].ip, "192.168.1.100");
        assert_eq!(dns_file.entries[2].hostnames.len(), 1);
        assert_eq!(dns_file.entries[2].hostnames[0], "test.local");
    }
    
    #[test]
    fn test_to_string() {
        let content = "# Comment line
127.0.0.1 localhost
::1 ip6-localhost
";
        let dns_file = DnsFile::from_content(content).unwrap();
        let output = dns_file.to_string();
        
        assert!(output.contains("# Comment line"));
        assert!(output.contains("127.0.0.1 localhost"));
        assert!(output.contains("::1 ip6-localhost"));
    }
    
    #[test]
    fn test_add_entry() {
        let content = "127.0.0.1 localhost
";
        let mut dns_file = DnsFile::from_content(content).unwrap();
        
        // Add to new IP
        dns_file.add_entry("192.168.1.10", "test.local").unwrap();
        
        assert_eq!(dns_file.entries.len(), 2);
        assert_eq!(dns_file.entries[1].ip, "192.168.1.10");
        assert_eq!(dns_file.entries[1].hostnames[0], "test.local");
        
        // Add to existing IP
        dns_file.add_entry("127.0.0.1", "another.local").unwrap();
        
        assert_eq!(dns_file.entries.len(), 2);  // Should still be 2 IPs
        assert_eq!(dns_file.entries[0].hostnames.len(), 2);  // But with 2 hostnames
        assert_eq!(dns_file.entries[0].hostnames[1], "another.local");
        
        // Try to add duplicate (should fail)
        let result = dns_file.add_entry("1.1.1.1", "localhost");
        assert!(result.is_err());
        
        // Invalid inputs
        assert!(dns_file.add_entry("999.0.0.1", "test2.local").is_err());
        assert!(dns_file.add_entry("1.1.1.1", "invalid-.local").is_err());
    }
    
    #[test]
    fn test_remove_entry() {
        let content = "127.0.0.1 localhost another.local
192.168.1.1 test.local
";
        let mut dns_file = DnsFile::from_content(content).unwrap();
        
        // Remove one of multiple hostnames
        dns_file.remove_entry("another.local").unwrap();
        
        assert_eq!(dns_file.entries.len(), 2);
        assert_eq!(dns_file.entries[0].hostnames.len(), 1);
        assert_eq!(dns_file.entries[0].hostnames[0], "localhost");
        
        // Remove last hostname for an IP (should remove the entire entry)
        dns_file.remove_entry("test.local").unwrap();
        
        assert_eq!(dns_file.entries.len(), 1);
        
        // Try to remove non-existent hostname
        let result = dns_file.remove_entry("nonexistent.local");
        assert!(result.is_err());
    }
    
    #[test]
    fn test_update_entry() {
        let content = "127.0.0.1 localhost
192.168.1.1 test.local
";
        let mut dns_file = DnsFile::from_content(content).unwrap();
        
        // Update an entry
        dns_file.update_entry("test.local", "10.0.0.1").unwrap();
        
        // Original IP should be gone
        assert_eq!(dns_file.entries.len(), 2);
        
        // Find the updated entry
        let updated_entry = dns_file.entries.iter()
            .find(|entry| entry.ip == "10.0.0.1")
            .unwrap();
            
        assert_eq!(updated_entry.hostnames.len(), 1);
        assert_eq!(updated_entry.hostnames[0], "test.local");
        
        // Try to update non-existent hostname
        let result = dns_file.update_entry("nonexistent.local", "1.1.1.1");
        assert!(result.is_err());
        
        // Invalid inputs
        assert!(dns_file.update_entry("localhost", "999.0.0.1").is_err());
    }
    
    #[test]
    fn test_corrupt_file_detection() {
        // Invalid IP
        let content = "999.0.0.1 localhost
";
        assert!(DnsFile::from_content(content).is_err());
        
        // Invalid hostname
        let content = "127.0.0.1 invalid$.com
";
        assert!(DnsFile::from_content(content).is_err());
        
        // Empty line with whitespace (should be OK)
        let content = "127.0.0.1 localhost
  
192.168.1.1 test.local
";
        assert!(DnsFile::from_content(content).is_ok());
    }
}

fn main() -> Result<()> {
    // Set up error handling for the CLI
    if let Err(e) = run() {
        eprintln!("{}", e);
        std::process::exit(1);
    }
    Ok(())
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    
    let hosts_file_path = hosts_file();
    
    match &cli.command {
        Commands::List { filter } => {
            let content = fs::read_to_string(&hosts_file_path)?;
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
            let content = fs::read_to_string(&hosts_file_path)?;
            let mut dns_file = DnsFile::from_content(&content)?;
            
            // Add new entry
            dns_file.add_entry(ip, hostname)?;
            
            // Write back to hosts file
            fs::write(&hosts_file_path, dns_file.to_string())?;
            
            println!("Added DNS entry: {} -> {}", hostname, ip);
        }
        
        Commands::Remove { hostname } => {
            // Backup before modification
            backup_hosts_file(&format!("Backup before removing {}", hostname))?;
            
            // Read and parse hosts file
            let content = fs::read_to_string(&hosts_file_path)?;
            let mut dns_file = DnsFile::from_content(&content)?;
            
            // Remove entry
            dns_file.remove_entry(hostname)?;
            
            // Write back to hosts file
            fs::write(&hosts_file_path, dns_file.to_string())?;
            
            println!("Removed DNS entry for {}", hostname);
        }
        
        Commands::Update { hostname, ip } => {
            // Backup before modification
            backup_hosts_file(&format!("Backup before updating {} to {}", hostname, ip))?;
            
            // Read and parse hosts file
            let content = fs::read_to_string(&hosts_file_path)?;
            let mut dns_file = DnsFile::from_content(&content)?;
            
            // Update entry
            dns_file.update_entry(hostname, ip)?;
            
            // Write back to hosts file
            fs::write(&hosts_file_path, dns_file.to_string())?;
            
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
