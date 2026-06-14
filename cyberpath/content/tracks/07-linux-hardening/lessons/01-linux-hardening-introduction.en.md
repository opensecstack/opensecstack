---
id: 01-linux-hardening-introduction
order: 1
duration_minutes: 60
---

# Lesson 1: Introduction to Linux Server Hardening

## Why Linux hardening is a NIS2 obligation

Linux is the dominant operating system for server workloads, cloud infrastructure, and network appliances in NIS2-scope environments. A default Linux installation is not a hardened Linux installation: package managers install many services not required for a given server's purpose; file permissions follow conservative but not minimally-privileged defaults; kernel parameters permit functionality that increases attack surface; and log collection is minimal. Hardening is the process of systematically reducing attack surface by removing unnecessary components, restricting configurations to least-privilege, enabling protective kernel features, and instrumenting the system for audit-grade monitoring.

NIS2 Article 21(2)(c) — business continuity — covers system availability, backup, and resilience. A compromised Linux server that was never hardened represents an availability risk: it is more easily exploited, more easily pivoted through, and harder to recover to a known-good state. Article 21(2)(h) — cryptography — applies where TLS termination, disk encryption, or SSH key management is in scope on Linux systems. Both measures are operationalised through hardening controls.

## The CIS Benchmark: a structured hardening baseline

The Center for Internet Security (CIS) publishes hardening benchmarks for major operating systems, applications, and cloud platforms. The CIS Linux Benchmark (available for Ubuntu, RHEL/CentOS/AlmaLinux, Debian, and others) is the most widely adopted Linux hardening standard. It is structured as an ordered list of recommendations, each with:

- A unique numeric identifier (e.g., `1.1.1.1`)
- A title and description of what to configure
- A rationale explaining the security benefit
- Audit instructions (how to check the current state)
- Remediation instructions (how to apply the control)
- An impact statement (what functionality may be affected)
- A scoring attribute: **Scored** (objective, automatable) or **Not Scored** (requires judgement)

CIS benchmarks have two profiles:

- **Level 1** — Recommended baseline. Controls that are widely applicable, have minimal performance impact, and are unlikely to break functionality in a standard server deployment.
- **Level 2** — Defense-in-depth. More restrictive controls for environments with heightened security requirements. May impact interoperability or performance.

For most NIS2-scope production servers, CIS Level 1 is the minimum acceptable baseline. Environments handling personal data, critical operational data, or serving as trust boundaries (jump hosts, bastion servers, PKI systems) should target Level 2.

## The attack surface categories addressed by hardening

Linux hardening controls span five broad categories:

**1. Filesystem configuration** — Restrict mount options (nodev, nosuid, noexec on non-root partitions), ensure separate partitions for `/tmp`, `/var`, `/var/log`, and `/home` to prevent one partition from filling and taking the system down, and set correct permissions on sensitive files and directories.

**2. Software minimisation** — Remove packages that are not required for the server's function. Each installed package is potential attack surface: it may have exploitable vulnerabilities, it may introduce unnecessary services, and it contributes to the complexity of the system. A web server does not need a print daemon, a mail transfer agent, or an X11 server.

**3. Services and network configuration** — Disable services not required for the server's function, configure the host-based firewall (iptables/nftables) to permit only required traffic, and disable IPv6 if not in use. Disable unused network protocols (DCCP, SCTP, RDS, TIPC) which may have exploitable implementations.

**4. Access control and authentication** — Enforce strong SSH configuration (disable password authentication, disable root login, use allowed ciphers and MACs), configure PAM for password complexity and account lockout, ensure users have minimum necessary privileges (no unnecessary sudo grants), and use file permissions correctly (no world-writable files or SUID binaries that are not required).

**5. Logging and auditing** — Configure `auditd` to log privileged operations, file system changes to sensitive paths, network configuration changes, and user authentication events. Configure `rsyslog` or `systemd-journald` to forward logs to a central log aggregator. Ensure log files are protected from modification by regular users.

## SELinux and AppArmor: mandatory access control

Standard Linux file permissions implement Discretionary Access Control (DAC): the owner of a file controls access to it. Mandatory Access Control (MAC) supplements DAC by enforcing a system-wide policy that cannot be overridden by the file owner. Linux MAC is implemented by two frameworks: SELinux (Security-Enhanced Linux, developed by the NSA, used by RHEL/CentOS/AlmaLinux/Fedora) and AppArmor (used by Ubuntu and Debian).

MAC provides defence-in-depth: even if an attacker exploits a vulnerability in a service running as a privileged user, the MAC policy restricts what that compromised process can do — limiting its ability to read sensitive files, write to protected paths, or make privileged system calls. A web server process confined by SELinux cannot read `/etc/shadow` even if the exploit grants it the permissions of the `www-data` user.

The key principle of MAC configuration is: enforce mode, not permissive mode. Permissive mode logs policy violations but does not block them — it is a diagnostic mode, not a security mode. A system in SELinux permissive mode is not protected by SELinux. Organisations that "enable SELinux" but leave it in permissive mode derive no MAC benefit.
