---
id: 02-linux-hardening-controls
order: 2
duration_minutes: 90
---

# Lesson 2: Applying Hardening Controls — SSH, Kernel, auditd, and Package Integrity

## SSH hardening: the most critical service

SSH is present on virtually every Linux server and is the primary remote administration vector. It is also the first target of opportunistic attackers: internet-facing SSH servers receive automated brute-force attempts within seconds of becoming reachable. SSH hardening is not optional.

The key configuration file is `/etc/ssh/sshd_config`. The following controls implement the CIS benchmark requirements and security best practices:

```text
# /etc/ssh/sshd_config — CIS Level 1 hardening

Protocol                        2
Port                            22       # change to non-standard port in high-risk environments

# Authentication controls
PermitRootLogin                 no
PasswordAuthentication          no       # public key only
PermitEmptyPasswords            no
ChallengeResponseAuthentication no
UsePAM                          yes

# Session controls
LoginGraceTime                  60
MaxAuthTries                    4
MaxSessions                     4
ClientAliveInterval             300
ClientAliveCountMax             0

# Feature restriction
AllowAgentForwarding            no
AllowTcpForwarding              no
X11Forwarding                   no
PrintMotd                       no

# Algorithm restriction (modern, secure ciphers only)
Ciphers             aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes128-gcm@openssh.com
MACs                hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms       curve25519-sha256,curve25519-sha256@libssh.org

# Logging
LogLevel            VERBOSE
```

After editing, validate and reload:

```bash
# Validate the configuration syntax
sshd -t

# Reload the service without dropping existing sessions
systemctl reload sshd
```

## Kernel hardening with sysctl

The Linux kernel exposes a large number of tuneable parameters via `/proc/sys/`, configurable persistently through `/etc/sysctl.conf` or files in `/etc/sysctl.d/`. Several parameters directly reduce attack surface:

```bash
# /etc/sysctl.d/99-hardening.conf

# Network hardening
net.ipv4.ip_forward                    = 0   # disable IP forwarding (unless this is a router)
net.ipv4.conf.all.send_redirects       = 0
net.ipv4.conf.default.send_redirects  = 0
net.ipv4.conf.all.accept_redirects     = 0
net.ipv4.conf.all.secure_redirects     = 0
net.ipv4.conf.all.accept_source_route  = 0
net.ipv4.icmp_echo_ignore_broadcasts   = 1
net.ipv4.tcp_syncookies                = 1   # SYN flood protection
net.ipv4.conf.all.rp_filter            = 1   # reverse path filtering

# Kernel hardening
kernel.dmesg_restrict                  = 1   # restrict dmesg to root
kernel.kptr_restrict                   = 2   # hide kernel pointers
kernel.randomize_va_space              = 2   # ASLR: full randomisation
kernel.yama.ptrace_scope               = 1   # restrict ptrace to parent processes
fs.protected_hardlinks                 = 1
fs.protected_symlinks                  = 1
fs.suid_dumpable                       = 0   # prevent SUID processes writing core dumps

# User namespace restriction (reduce container escape surface)
kernel.unprivileged_userns_clone       = 0   # Debian/Ubuntu specific
```

Apply immediately without reboot:

```bash
sysctl --system
```

## Configuring auditd for NIS2-grade logging

`auditd` is the Linux kernel audit daemon. It intercepts system calls and logs events matching configured rules to `/var/log/audit/audit.log`. For NIS2-scope systems, the audit configuration should capture all events required to reconstruct a security incident timeline.

The audit rules are loaded at boot from `/etc/audit/rules.d/`. A comprehensive baseline:

```bash
# /etc/audit/rules.d/99-nistcompliance.rules

# Ensure the buffer is large enough
-b 8192

# Watch for changes to authentication configuration
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k privilege-escalation
-w /etc/sudoers.d/ -p wa -k privilege-escalation

# Watch for SSH configuration changes
-w /etc/ssh/sshd_config -p wa -k sshd-config

# Log privileged command execution
-a always,exit -F arch=b64 -S execve -F euid=0 -k root-commands

# Log failed authentication
-a always,exit -F arch=b64 -S open -F exit=-EACCES -k access-denied

# Log use of sudo
-w /usr/bin/sudo -p x -k privilege-escalation
-w /usr/bin/su -p x -k privilege-escalation

# Immutable rule set (must reboot to change rules)
-e 2
```

After modifying rules, reload:

```bash
augenrules --load
systemctl restart auditd
```

Query audit events:

```bash
# All events tagged with the 'identity' key in the last hour
ausearch -k identity --start recent

# All sudo uses in the last 24 hours
ausearch -k privilege-escalation --start today
```

## Package integrity and supply chain controls

The package supply chain is an often-overlooked attack surface. An attacker who compromises a package repository or a package maintainer's signing key can deliver malicious packages to any system that trusts that repository. Controls:

**GPG key verification** — All major Linux distributions sign packages with GPG. Never disable GPG verification (`apt --allow-unauthenticated` or `rpm --nogpgcheck`). Validate that only trusted keys are in the keyring:

```bash
# List trusted apt keys (Ubuntu/Debian)
apt-key list 2>/dev/null || gpg --no-default-keyring \
  --keyring /etc/apt/trusted.gpg.d/*.gpg --list-keys

# Verify a specific package's signature (RPM-based)
rpm -K package.rpm
```

**Integrity checking with AIDE** — AIDE (Advanced Intrusion Detection Environment) builds a database of file checksums, permissions, and metadata for critical system files. Running AIDE checks detects post-compromise file modification:

```bash
# Initialize the AIDE database (run after hardening, before production use)
aide --init && mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Run an integrity check (schedule this via cron/systemd timer)
aide --check
```

**Automated updates for security patches** — Unpatched vulnerabilities are the leading initial access vector. Configure automatic security updates:

```bash
# Ubuntu/Debian: unattended-upgrades
dpkg-reconfigure --priority=low unattended-upgrades

# RHEL/AlmaLinux: dnf-automatic
systemctl enable --now dnf-automatic.timer
```

## Running the CIS benchmark scan

The CIS provides an official benchmark assessment tool (CIS-CAT Pro) for automated scoring. OpenSCAP is the open-source alternative, using SCAP content derived from the CIS benchmarks:

```bash
# Run an OpenSCAP assessment against the CIS Level 1 profile
oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_cis_level1_server \
  --report /tmp/cis-report.html \
  --results /tmp/cis-results.xml \
  /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml

# Summary pass/fail count
grep -c 'result>pass' /tmp/cis-results.xml
grep -c 'result>fail' /tmp/cis-results.xml
```

In the CyberPath lab exercise, you will run this scan against a deliberately under-hardened Ubuntu 22.04 container, apply a set of remediation controls, and re-run the scan to measure score improvement.
