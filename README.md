# DNS Edit

A command-line tool to manage your `/etc/hosts` DNS entries with built-in version control.

## Features

- List, add, remove, and update DNS entries
- Automatic validation of IP addresses and hostnames
- Git-based version control with automatic backups
- Restore previous versions from backup history
- Simple, intuitive command-line interface

## Installation

```bash
cargo install dns_edit
```

Or build from source:

```bash
git clone https://github.com/yourusername/dns_edit.git
cd dns_edit
cargo build --release
```

## Usage

This tool should be run with sufficient permissions to modify `/etc/hosts` (usually with sudo).

### List all DNS entries
```bash
sudo dns_edit list
# Filter entries
sudo dns_edit list -f example.com
```

### Add a new DNS entry
```bash
sudo dns_edit add 127.0.0.1 example.local
```

### Remove a DNS entry
```bash
sudo dns_edit remove example.local
```

### Update an existing DNS entry
```bash
sudo dns_edit update example.local 192.168.1.10
```

### Restore from backup
```bash
# Restore from latest backup
sudo dns_edit restore
# Restore from specific commit
sudo dns_edit restore -c abc123
```

## Backups

All modifications to the hosts file are automatically backed up to `/usr/local/dns` in a git repository. Each operation creates a separate commit, making it easy to track changes and restore previous versions.

## License

MIT License