use std::fs;
use std::process::Command;
use tempfile::tempdir;

// These tests are designed to be run with `cargo test --test cli_test`

#[test]
fn test_cli_add_remove_update() {
    // Create a temporary directory for our test
    let temp_dir = tempdir().unwrap();
    let hosts_path = temp_dir.path().join("hosts");
    
    // Create a test hosts file
    let test_content = "# Test hosts file
127.0.0.1 localhost
";
    fs::write(&hosts_path, test_content).unwrap();
    
    // Build the binary (assumes we're running this from the project root)
    let status = Command::new("cargo")
        .args(["build"])
        .status()
        .unwrap();
    assert!(status.success());
    
    // Test environment variables to override constants
    let backup_dir_path = temp_dir.path().join("dns");
    let env_vars = [
        ("HOSTS_FILE", hosts_path.to_str().unwrap()),
        ("BACKUP_DIR", backup_dir_path.to_str().unwrap()),
    ];
    
    // Test adding a new entry
    let output = Command::new("./target/debug/dns_edit")
        .args(["add", "192.168.1.10", "test.example.com"])
        .envs(env_vars.iter().cloned())
        .output()
        .unwrap();
    
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Added DNS entry"));
    
    // Verify the file was updated
    let content = fs::read_to_string(&hosts_path).unwrap();
    assert!(content.contains("192.168.1.10 test.example.com"));
    
    // Test listing entries
    let output = Command::new("./target/debug/dns_edit")
        .args(["list"])
        .envs(env_vars.iter().cloned())
        .output()
        .unwrap();
    
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("localhost -> 127.0.0.1"));
    assert!(stdout.contains("test.example.com -> 192.168.1.10"));
    
    // Test listing with filter
    let output = Command::new("./target/debug/dns_edit")
        .args(["list", "-f", "example"])
        .envs(env_vars.iter().cloned())
        .output()
        .unwrap();
    
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("localhost"));
    assert!(stdout.contains("test.example.com"));
    
    // Test updating an entry
    let output = Command::new("./target/debug/dns_edit")
        .args(["update", "test.example.com", "10.10.10.10"])
        .envs(env_vars.iter().cloned())
        .output()
        .unwrap();
    
    assert!(output.status.success());
    
    // Verify the file was updated
    let content = fs::read_to_string(&hosts_path).unwrap();
    assert!(!content.contains("192.168.1.10 test.example.com"));
    assert!(content.contains("10.10.10.10 test.example.com"));
    
    // Test removing an entry
    let output = Command::new("./target/debug/dns_edit")
        .args(["remove", "test.example.com"])
        .envs(env_vars.iter().cloned())
        .output()
        .unwrap();
    
    assert!(output.status.success());
    
    // Verify the file was updated
    let content = fs::read_to_string(&hosts_path).unwrap();
    assert!(!content.contains("test.example.com"));
}

#[test]
fn test_cli_error_handling() {
    // Create a temporary directory for our test
    let temp_dir = tempdir().unwrap();
    let hosts_path = temp_dir.path().join("hosts");
    
    // Create a test hosts file
    let test_content = "# Test hosts file
127.0.0.1 localhost
";
    fs::write(&hosts_path, test_content).unwrap();
    
    // Test environment variables to override constants
    let backup_dir_path = temp_dir.path().join("dns");
    let env_vars = [
        ("HOSTS_FILE", hosts_path.to_str().unwrap()),
        ("BACKUP_DIR", backup_dir_path.to_str().unwrap()),
    ];
    
    // Test invalid IP - we'll just check it fails
    let output = Command::new("./target/debug/dns_edit")
        .args(["add", "999.999.999.999", "test.example.com"])
        .envs(env_vars.iter().cloned())
        .output()
        .unwrap();
    
    assert!(!output.status.success());
    
    // Test invalid hostname - we know the program rejects it, but we can just
    // check the exit code rather than the exact error message which might change
    let output = Command::new("./target/debug/dns_edit")
        .args(["add", "127.0.0.1", "invalid$.example.com"])
        .envs(env_vars.iter().cloned())
        .output()
        .unwrap();
    
    assert!(!output.status.success()); // Just check it failed
    
    // Test hostname that doesn't exist
    let output = Command::new("./target/debug/dns_edit")
        .args(["remove", "doesnotexist.example.com"])
        .envs(env_vars.iter().cloned())
        .output()
        .unwrap();
    
    assert!(!output.status.success());
}