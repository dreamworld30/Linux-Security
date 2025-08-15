## **Physical Security in Cybersecurity**

Physical security is a fundamental but often overlooked part of protecting computers. It focuses on safeguarding actual hardware from theft, damage, or unauthorized physical access.

**Main Threats**

1. **Theft or Damage of Hardware** – Beyond the inconvenience of replacing devices, data loss can be permanent and damaging.

2. **Unauthorized Data Access** – Someone with physical access can copy, alter, or delete sensitive information.

3. **System Compromise** – Attackers can install malware or backdoors if they gain direct access.

**Mitigation Strategies**

* Secure racks, locking cables, and restricted server rooms.

* Disable unused ports and harden the operating system.

* Implement layered defenses: cameras, security guards, and electronic protections.

---

## **Single-User Mode in Linux**

Single-user mode is designed for troubleshooting and disaster recovery, not for daily operations.

**Modes**

* **Bare Shell** – Minimal environment before system services start.

* **Systemd Rescue Target** – Starts a limited set of services and mounts local filesystems read-only.

**Security Risks**

* Often grants root access without a password.

* Allows remounting filesystems as read/write to make changes.

* Even with root disabled, physical access can still enable it.

**How to Access**

* Command line: `systemctl isolate rescue.target`

* During boot: hold Left Shift → GRUB menu → Press E → Edit kernel line

  * Add `systemd.unit=rescue.target` or `init=/bin/bash`

**Mitigation**

* Add a bootloader password.

* Use disk encryption to protect sensitive data.

---

## **Securing the Bootloader in Linux (GRUB)**

The bootloader (GRUB) starts before the operating system and can be modified to bypass security controls.

**Risks Without Protection**

* Kernel parameters can disable security or boot into single-user mode.

* Physical access can give root access by default.

**How to Secure GRUB**

Generate a password hash:

 `grub-mkpasswd-pbkdf2`

1. 

Copy the hash and edit `/etc/grub.d/40_custom`:

 `set superusers="admin"`  
`password_pbkdf2 admin <paste_hash_here>`

2. 

Update GRUB and reboot:

 `sudo update-grub`

3. 

**Additional Protections**

* BIOS/EFI password

* Full disk encryption

* Physical security

**Caution:** Losing the GRUB password can lock you out. Keep offline recovery credentials.

---

## **Disk Encryption in Linux**

Disk encryption protects stored data from unauthorized access, particularly in the case of device theft or improper disposal.

**Threats Addressed**

* Stolen laptops or drives

* Discarded or recycled storage devices

**How It Works**

* Requires a password or key to access.

* Protection is active when the disk is unmounted.

**Types**

1. **Full Disk Encryption (FDE)**

2. **Volume/Partition Encryption** (e.g., LUKS)

3. **File-Level Encryption**

**Linux Example Using LUKS**

`fdisk /dev/vdb`  
`cryptsetup -v luksFormat /dev/vdb1`  
`cryptsetup -v luksOpen /dev/vdb1 MyData`  
`mkfs.ext4 /dev/mapper/MyData`  
`mkdir /mnt/MyData`  
`mount /dev/mapper/MyData /mnt/MyData`  
`chown username:group /mnt/MyData`  
`umount /mnt/MyData`  
`cryptsetup -v luksClose MyData`

 **Considerations**

* Boot-time passwords can be inconvenient.

* LUKS header damage \= permanent data loss.

* Never store keys on unencrypted drives.

# **Operating System Security on Linux**

Keeping your Linux system secure involves more than just installing software—it’s about maintaining updates, controlling malware, monitoring system health, and enforcing strict access policies. Here’s a comprehensive guide.

---

## **1\. Software Updates and Patches**

### **Importance of Updates**

Software is never perfect; vulnerabilities are discovered regularly. Updates fix:

* Security issues

* Stability problems

* Occasionally, new features

### **Sources of Updates**

Linux updates usually come from distribution repositories:

* **APT (Debian/Ubuntu):** Two-step (`update list → install updates`)

* **DNF/YUM (Red Hat/Fedora):** One-step (`update & install`)

For large deployments or limited internet access, organizations may host internal mirrors.

### **Prioritizing Updates**

* Critical updates (e.g., RCE bugs) → install first

* Use tools like `unattended-upgrades` to automate important updates

* Regular updates still follow a schedule

### **Testing Updates**

* Test updates in non-production environments

* Package pinning can maintain consistent versions but may cause dependency conflicts

### **Patches vs Updates**

* **Patches:** Instructions applied to source code

* **Updates:** Pre-built packages via package managers

### **Service Impact**

* Some updates require service restarts

* Kernel/firmware updates usually require a full reboot

* Commands to check:

  * **Debian:** `/var/run/reboot-required`

  * **Red Hat:** `needs-restarting`

### **Firmware and Drivers**

* Firmware updates fix hardware bugs

* Drivers installed manually need separate updates

### **Non-repository Software**

* Requires manual updates:

  1. Download the latest version

  2. Verify integrity (hash check)

  3. Install manually or via build scripts

### **Alternative Package Managers**

* Snap, FlatPak, pip, and npm have their own update mechanisms

* Consider containerization to limit exposure

### **Update Strategy**

* Choose between automatic or controlled updates

* Use configuration management tools for rolling deployments

**Takeaway:** Keeping OS, software, and hardware updated is critical for security.

---

## **2\. Malware and Viruses**

### **Linux is Not Immune**

Linux used to be a smaller target, but now it’s widely used in e-commerce, apps, and infrastructure.

### **What is Malware?**

Malware is software designed to:

* Steal data or resources

* Spread to other systems

* Participate in attacks

**Viruses** are a type of malware that infects files.

### **How Malware Gets on Linux**

* Installed intentionally or accidentally

* Tainted software from unofficial sources

* Compromised services (malicious ads, infected downloads)

* Email/file attachments

### **Preventing Malware**

* Only install trusted software

* Use official/verified repositories

* Check file integrity (hashes, digital signatures)

* Avoid unknown download links

### **Detecting Malware**

* Obvious: Ransomware

* Hidden: Steals data quietly, unusual network activity, or suspicious processes

* Use periodic scans

### **Malware Scanning Tools**

* ClamAV – free, open-source

* Commercial: CrowdStrike, Carbon Black, FireEye

* Methods:

  * Signature-based (known malware fingerprints)

  * Heuristic (suspicious behavior)

### **Quarantine & Deletion**

* Tools can quarantine or delete infected files

* Prevention is always better than remediation

### **Industry Requirements**

* Finance and data protection often require anti-malware

* Scanning is a good security practice

---

## **3\. Health Checks & Attestation**

### **Why They Matter**

* Know hardware/software status

* Monitor security, updates, and storage

* Maintain compliance

### **Health Checks**

Track:

* Hardware (CPU, RAM, storage)

* Software versions

* Update status

* Storage usage

* Logged-in users

### **Attestation**

* Systems report health to a central service

* Key for Zero Trust Security

* Non-compliant devices may be denied access

### **Tools**

* `osquery` – SQL-like queries for system health

* CrowdStrike – commercial health checks & remediation

* Orchestration/config management tools

Key takeaway: Health checks \+ attestation \= secure and compliant systems

---

## **4\. SELinux and AppArmor**

### **SELinux (Security-Enhanced Linux)**

* Red Hat ecosystem (RHEL, Fedora)

* Adds Mandatory Access Control (MAC) on top of standard permissions

* Commands:

  * `chcon` – set file context

  * `ls -Z` – view context

  * `sestatus` – check status

  * `setenforce 1/0` – enable/disable enforcement

**Modes:**

* Permissive → logs violations

* Enforcing → blocks violations

### **AppArmor**

* Debian ecosystem (Ubuntu, Debian, Mint)

* Restricts programs via profiles in `/etc/apparmor.d`

* Commands:

  * `aa-status` – check active profiles

  * `aa-complain` / `aa-enforce` – switch modes

  * `aa-disable` – disable profile

Both enhance security beyond standard permissions. Misconfiguration can cause issues; don’t disable casually.

---

## **5\. Services and Daemons**

### **Definition**

* Software that runs in the background, waiting for requests

* Examples: web servers, file servers, databases

### **Security Considerations**

* Run services with **least privilege**

* Separate public/private services

* Use containers if resources are limited

### **Managing Services**

* `systemd` commands:

  * `systemctl start/stop/restart <service>`

  * `systemctl enable/disable <service>`

  * `systemctl mask <service>` – completely block service

Best practices: understand services, monitor, update, disable unused services, and dedicate hardware when possible.

---

## **6\. Logging**

### **Importance**

* Logs show system operations, errors, and events

* Types: system logs, application logs, service logs

* Protect logs from attackers

### **Linux Logging**

* `systemd-journald` centralizes logs

* Forwarded to `/var/log/syslog` or `/var/log/auth.log`

* Manual services can use `logger` command

### **Viewing Logs**

* `journalctl` – navigate logs (`F` forward, `B` back, `Q` quit)

Logging is essential for troubleshooting and security monitoring.

## **3\. Account Security**

### **Purpose of User Account Policies**

* Protect user data and system integrity.

* Policies fall into two main groups:

  1. **Account structure and defaults** – how new accounts are created and initial settings.

  2. **Authentication experience** – rules affecting login behavior (password complexity, lockouts, etc.).

---

### **Account Defaults and Settings**

**Key files:**

* `/etc/adduser.conf` – defaults for new users created with `adduser`

  * Whether a new user has a private group

  * Initial group membership

  * Home directory layout and permissions (restrictive permissions recommended)

  * Allowed username characters

  * Template home directories: `/etc/skel` (files copied to new users’ home directories)

* `/etc/login.defs` – password aging and login defaults (may vary by distro)

**Other considerations:**

* Distribution-specific files may further control user creation.

---

### **Controlling User Privileges**

* **Superuser access:** Manage who can use `sudo` or root privileges.

* **Service-specific login:** Control access via SSH, Samba, etc.

* **Resource limits:** Use `ulimit` to restrict CPU, memory, storage.

---

### **Authentication and Password Policies**

**PAM (Pluggable Authentication Modules):**

* Modular system controlling authentication methods.

* Enforces password policies, login rules, hardware authentication, and integration with LDAP.

**PAM Configuration Files:**

* `/etc/pam.d/common-password` – system-wide password policies

* `/etc/security/pwquality.conf` – password quality

* `/etc/security/faillock.conf` – account lockouts

* `/etc/security/time.conf` – login time restrictions

**Password Quality Example:**

1. Install module: `apt install libpam-pwquality`

2. Configure in `/etc/security/pwquality.conf` (min length, digits, uppercase, lowercase, special characters, dictionary checks)

3. Force password change: `passwd -e username`

**Best Practices:**

* Preserve default settings as comments

* Test configurations carefully

---

### **Controlling Superuser Access**

**Root vs. Sudo:**

* **Root:** full system control; sharing root password is risky

* **Sudo:** allows users to perform admin tasks without knowing root password

**Editing sudoers file:**

* Use `visudo` to avoid syntax errors

* Modular changes: `/etc/sudoers.d`

**File Structure:**

* Defaults: global sudo behavior (`env_reset`, `secure_path`, `mail_badpass`)

* User/Group specs: `who where = as_whom what`

**Managing Access:**

* Add users to `sudo` (Debian) or `wheel` (Red Hat) groups

* Granular access: restrict commands

**Best Practices:**

* Avoid sharing root password

* Prefer `sudo` over direct root login

* Use `visudo` and `/etc/sudoers.d`

---

### **Using sudo**

1. **Create a new user:** `sudo adduser mary`

2. **Check groups:** `id mary`

3. **Test sudo access:** `sudo ls /` (fails if not in sudo group)

4. **Grant sudo:** `sudo usermod -aG sudo mary` (Debian) or `wheel` (Red Hat)

5. **Check sudo privileges:** `sudo -l`

6. **Root shell options:** `sudo -s` (regular), `sudo -i` (login shell)

7. **Run commands:** `sudo ls /`

8. **Expire session immediately:** `sudo -k`

**Best Practices:**

* Use sudo sparingly

* Only for tasks requiring root privileges

---

### **Securing the Root Account**

**Why:** Direct root login is risky; use sudo instead.

**Disabling Root:**

1. **Lock root password:**

   * `sudo passwd -l root` or `sudo usermod -L root`

   * `!` in `/etc/shadow` indicates locked account

2. **Change root shell:**

   * `sudo usermod -s /sbin/nologin root` (blocks normal login shell)

**Additional Measures:**

* Disable root SSH login: `/etc/ssh/sshd_config → PermitRootLogin no`

* Root hardening does **not** protect against physical access

**Best Practices:**

* Use sudo for administrative tasks

* Lock root password and/or set shell to `/sbin/nologin`

* Disable SSH root login

## **1\. File Permissions**

**Purpose:**

* Protect files on multi-user systems from unauthorized read, write, or execute actions.

**Two Sets of Three:**

* **Who:** User (owner), Group, Others

* **Actions:** Read (r), Write (w), Execute (x)

* **Representation:** 9-character string (rwx for user, group, others)

  * Example: `rwxr-xr--` → User: rwx, Group: r-x, Others: r--

**Changing Ownership:**

* `chown` → change owner or group

* `chgrp` → change group

**Changing Permissions:**

* **Symbolic Notation:**

  * `u` \= user, `g` \= group, `o` \= others, `a` \= all

  * `+` add, `-` remove, `=` set exact

  * Examples:

    * `chmod u+x file.txt` → add execute for user

    * `chmod g-w file.txt` → remove write for group

* **Numeric (Octal) Notation:**

  * Read \= 4, Write \= 2, Execute \= 1

  * Add for each role → e.g., `rwxr-xr-- = 754`

  * Example: `chmod 754 file.txt`

**Practical Examples:**

`echo "This is a text file" > file.txt`  
`ls -l file.txt`  
`chmod -w file.txt       # remove write access for everyone`  
`chmod u+w file.txt      # restore write for user`

**Notes:**

* Permissions reference numeric user/group IDs.

* Filesystems like ExFAT do not preserve permissions.

* Root overrides permissions.

* Use centralized user management for multi-system environments.

---

## **2\. Special Modes**

| Mode | Purpose | Command Example | Notes |
| ----- | ----- | ----- | ----- |
| **SetGID** | Files inherit directory’s group | `chmod g+s /shared` or `chmod 2XXX /shared` | Useful for shared folders |
| **SetUID** | Execute file with owner’s privileges | `chmod u+s file` or `chmod 4XXX file` | Risky if owner is root |
| **Sticky Bit** | Only file owner can delete file in writable directory | `chmod +t /tmp` or `chmod 1XXX /tmp` | Common in `/tmp` |

**Key Takeaways:**

* Add-ons to normal permissions, not replacements.

* Combine with rwx for secure shared spaces.

---

## **3\. Access Control Lists (ACLs)**

**Why ACLs?**

* Standard permissions: 1 owner, 1 group, everyone else.

* ACLs: Multiple users and groups can have custom access.

**Key Commands:**

| Action | Command Example | Notes |
| ----- | ----- | ----- |
| Install tools | `sudo apt install acl` | Required first |
| Grant access | `setfacl -m u:tom:r file.txt` | Tom: read only |
| Grant full access | `setfacl -m u:mary:rwx file.txt` | Mary: full access |
| Grant group access | `setfacl -m g:staff:rw file.txt` | staff group: read/write |
| View ACLs | `getfacl file.txt` | Shows all ACL entries |
| Remove access | `setfacl -x u:tom file.txt` | Removes Tom’s ACL entry |

**Notes:**

* `+` in `ls -l` indicates ACLs are set.

* Filesystem must support ACLs (`tune2fs`, mount options).

* Copying files to unsupported FS → ACLs lost.

**Summary:** ACLs provide flexible, per-user/group permissions without changing ownership.

---

## **4\. File Attributes & Extended Attributes**

| Feature | Purpose | Commands | Examples | Security Use |
| ----- | ----- | ----- | ----- | ----- |
| **File Attributes (chattr)** | Control file behavior at OS level | `chattr`, `lsattr` | `+a` append-only, `+i` immutable | Protect critical files from editing/deletion |
| **Extended Attributes (xattr)** | Store extra metadata (key-value) | `setfattr`, `getfattr` | `setfattr -n user.note -v "something" file.txt` | Can store sensitive info; remove before sharing |

**Notes:**

* File attributes → flags (on/off)

* Extended attributes → key-value pairs, can be used by SELinux/AppArmor

* Security impact: chattr protects integrity; xattrs can hold sensitive metadata

## **1\. Network Services**

**Definition:** Programs that allow communication between computers.

**Examples:**

* **Public:** Websites, public APIs

* **Private:** SSH access, employee database

**Importance:**

* **Public:** Accessible by anyone → higher risk if insecure.

* **Private:** Restricted access → must be protected.

---

## **2\. Securing Public Services**

* **Configuration:** Strong passwords, 2FA

* **Access Rules:** Use allowlists/denylists

* **Encryption:** Modern encryption protocols

* **Session Control:** Manage and end sessions

* **Input Sanitization:** Protect against malware/exploits

* **Updates:** Apply security patches promptly

* **Network Setup:**

  * Place in DMZ (isolated zone)

  * Avoid mixing public/private services on the same host

  * Use load balancers, caching, and reverse proxies for traffic spikes or DoS protection

---

## **3\. Securing Private Services**

* **VPN:** Creates an encrypted tunnel for secure access

* **Access Control:** Use centralized systems like Active Directory or SSO

* **Updates & Monitoring:** Keep private services patched and configurations checked

---

## **4\. Key Takeaways**

* Public: Secure, patch, isolate

* Private: VPN \+ strong access control

* Always monitor, update, and review configurations

---

## **5\. Ports**

**Definition:** Allow services to communicate over a network.

* **Ranges:**

  * 0–1023 → Well-known ports (require superuser)

  * 1024+ → Non-privileged

**Common Well-Known Ports:**

* SSH → 22

* IMAP → 143

* HTTPS → 443

**Reasons to Change Ports:**

* Obscure service (security by obscurity)

* Run multiple instances

* Downside → complexity and misconfiguration risk

**Linux Tools to Check Ports:**

* `ss -tu` → TCP & UDP

* `ss -tun` → Port numbers

* `sudo ss -tunp` → Processes using ports

**Non-Standard Ports to Watch:**

* 3000, 8080, 8000 → Web servers/testing

* 3306 → MySQL

* 5432 → PostgreSQL

**Best Practices:**

* Don’t rely on port numbers alone

* Regular scans (local: ss; remote: nmap with permission)

* Consider performance: dedicated interfaces or hardware

---

## **6\. Hardening SSH**

* **Why:** SSH allows remote admin access → high-risk target

* **Config Location:** `/etc/ssh/sshd_config`

* **Key Steps:**

  * Disable root login: `PermitRootLogin no`

  * Use SSH keys instead of passwords (`PubkeyAuthentication yes`, `PasswordAuthentication no`)

  * Store public keys in `~/.ssh/authorized_keys`

  * Generate & copy keys: `ssh-keygen` → `ssh-copy-id username@host`

* **Optional:** Change port, restrict listening addresses, limit features, control ciphers

* **Apply Changes:** `sudo systemctl restart ssh` (ensure key login works first\!)

* **Extra Protection:** VPN access, bastion host

* **Use Cases:** Secure file transfers (SFTP, rsync), tunneling traffic

---

## **7\. Firewalls**

**Purpose:** Control access to network ports, limit exposure to attacks.

**Default Behavior:**

* Outbound traffic: usually allowed

* Inbound traffic: usually blocked except responses

**Linux Firewall Software:**

* IP Tables → traditional

* NF Tables → newer

* Tools: UFW (Ubuntu/Debian), firewalld (Red Hat/CentOS/Fedora)

**Basic Rules Example:**

`sudo ufw allow 22/tcp       # Ubuntu/Debian`  
`sudo ufw enable`  
`sudo firewall-cmd --add-port=22/tcp --zone=public  # Red Hat/CentOS`  
`sudo firewall-cmd --reload`

* Use service names instead of port numbers: `sudo ufw allow ssh`

**Advanced Options:**

* Restrict by source IP/network

* Packet routing for advanced users

**Monitoring & Verification:**

* `sudo ufw status` → Ubuntu/Debian

* `sudo firewall-cmd --list-all` → Red Hat/CentOS

* `sudo iptables -L -n` → Dump rules

**Best Practices:**

* Always run a firewall

* Write precise rules (port, protocol, source)

* Automate rule management for larger deployments

Certificate of Completion: [https://www.linkedin.com/learning/certificates/f71234345ec7b598dcf8d7f6c923f33322657364035005bbf19f8fc25a322419?trk=share\_certificate](https://www.linkedin.com/learning/certificates/f71234345ec7b598dcf8d7f6c923f33322657364035005bbf19f8fc25a322419?trk=share_certificate)