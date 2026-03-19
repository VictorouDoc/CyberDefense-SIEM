# nftables Firewall Deployment Report

**Date:** 2026-02-06
**Target:** [ORGANIZATION] Bastion Host ([REDACTED_OS])
**Author:** Blue Team - Security Engineering

---

## 1. Context

The bastion host is the single gateway between the external internet and the internal hospital network (192.168.1.0/24). Prior to this deployment, the only firewall mechanism was a **reactive SIEM-based auto-ban** system that applied individual `iptables -I INPUT -s <IP> -j DROP` rules when attacks were detected.

### Problems with the previous approach

| Problem | Impact |
|---------|--------|
| No default-deny policy | All ports open to all IPs until an attack is detected |
| No forward chain filtering | External traffic could reach any internal host unrestricted |
| No persistence | All ban rules lost on reboot |
| No stateful tracking | No distinction between new, established, or invalid connections |
| No rate limiting | SYN floods and ICMP floods not mitigated at kernel level |
| Detection must succeed first | Zero-day or unrecognized attacks pass through freely |

---

## 2. Solution: nftables

We deployed **nftables**, the native Linux firewall framework on Ubuntu 24.04, replacing the raw iptables approach. nftables provides:

- **Default-deny posture** on INPUT and FORWARD chains
- **Stateful connection tracking** (established/related/invalid)
- **Named sets** for dynamic IP management (whitelist + banned)
- **Per-element timeouts** on the banned set (auto-expiring bans)
- **Atomic rule loading** (no gaps during rule updates)
- **Persistence across reboots** via systemd service

---

## 3. Files Created / Modified

| File | Action | Description |
|------|--------|-------------|
| `firewall/nftables.conf` | **Created** | Main nftables ruleset |
| `scripts/setup-nftables.sh` | **Created** | Installation and deployment script |
| `siem/app/routes/firewall.py` | **Modified** | SIEM auto-ban now uses nftables sets instead of raw iptables |
| `CONTEXT.md` | **Modified** | Added nftables documentation |

---

## 4. Ruleset Architecture

### 4.1 Network Topology

```
Internet
    |
  [eth0] 10.0.0.15/24   ← External / Management
    |
  BASTION (nftables)
    |
  [eth1] 192.168.1.100/24  ← Internal hospital network
    |
    ├── 192.168.1.30   Storage (Samba)    ← BLOCKED from external
    ├── 192.168.1.71   Orthanc (DICOM)    ← BLOCKED from external
    ├── 192.168.1.102  EHR (Apache)       ← HTTP/HTTPS allowed
    ├── 192.168.1.106  Redis              ← BLOCKED from external
    └── 192.168.1.111  Mail (SMTP/POP3)   ← Mail ports allowed
```

### 4.2 INPUT Chain (policy: DROP)

```
1. ct state established,related  → ACCEPT
2. ct state invalid              → DROP
3. loopback (lo)                 → ACCEPT
4. src in @banned                → DROP (counter)
5. src in @whitelist             → ACCEPT
6. ICMP echo-request             → ACCEPT (rate: 5/s)
7. SYN packets                   → ACCEPT (rate: 50/s, else DROP)
8. eth0: SSH (22, 221-230)       → ACCEPT
9. eth0: SIEM (8080-8090)        → ACCEPT
10. eth0: HTTP/S (80, 443)       → ACCEPT
11. eth0: Suricata (1514)        → ACCEPT
12. eth0: DNS (53)               → ACCEPT
13. eth1: 192.168.1.0/24         → ACCEPT (internal trust)
14. Everything else              → LOG + DROP
```

### 4.3 FORWARD Chain (policy: DROP)

```
1. ct state established,related       → ACCEPT
2. ct state invalid                    → DROP
3. src in @banned                      → DROP
4. eth1 → eth0 (outbound)             → ACCEPT
5. eth0 → eth1: EHR (80, 443)         → ACCEPT
6. eth0 → eth1: Mail (25, 110, etc.)  → ACCEPT
7. eth0 → eth1: DNS (53)              → ACCEPT
8. eth0 → eth1: Storage SMB           → EXPLICIT DROP
9. eth0 → eth1: Redis 6379            → EXPLICIT DROP
10. eth0 → eth1: DICOM 4242/8042      → EXPLICIT DROP
11. Everything else                    → LOG + DROP
```

### 4.4 Named Sets

| Set | Type | Purpose |
|-----|------|---------|
| `whitelist` | Static IPv4 | IPs that bypass all filtering (bastion, gateways, internal servers) |
| `banned` | Dynamic IPv4 with timeout | IPs blocked by SIEM auto-ban, auto-expire after set duration |
| `ratelimit_syn` | Dynamic with timeout | Internal tracking for SYN rate limiting |

---

## 5. SIEM Integration

The SIEM's `apply_firewall_ban()` function was updated to:

1. **Primary**: Use `nft add/delete element inet filter banned { <IP> timeout <N>s }` to dynamically manage the nftables banned set
2. **Fallback**: If nft fails (e.g., set doesn't exist), fall back to `iptables -I/-D` for backward compatibility
3. **Timeout support**: Auto-bans include a timeout so they expire both in nftables and in the database

### Ban flow

```
Attack detected by SIEM analyzer
        ↓
auto_ban_ip() called
        ↓
BannedIP record created in SQLite (with expires_at)
        ↓
nft add element inet filter banned { <IP> timeout 3600s }
        ↓
Kernel immediately drops all packets from that IP
        ↓
After timeout: nftables auto-removes the element
```

---

## 6. Deployment Instructions

```bash
# On the bastion host:
sudo bash scripts/setup-nftables.sh
```

The script will:
1. Install nftables (if needed)
2. Disable conflicting firewalls (UFW, iptables-persistent)
3. Back up any existing `/etc/nftables.conf`
4. Validate the new ruleset syntax
5. Deploy to `/etc/nftables.conf`
6. Enable IP forwarding (`net.ipv4.ip_forward=1`)
7. Load the ruleset and enable the systemd service
8. Print a verification summary

---

## 7. Operational Commands

```bash
# View full ruleset
nft list ruleset

# View currently banned IPs
nft list set inet filter banned

# View whitelist
nft list set inet filter whitelist

# Manually ban an IP for 1 hour
nft add element inet filter banned { 1.2.3.4 timeout 1h }

# Manually ban permanently
nft add element inet filter banned { 1.2.3.4 }

# Unban an IP
nft delete element inet filter banned { 1.2.3.4 }

# Check service status
systemctl status nftables

# View firewall drop logs
journalctl -k | grep nftables

# Reload ruleset after editing
nft -f /etc/nftables.conf
```

---

## 8. Security Posture: Before vs After

| Aspect | Before | After |
|--------|--------|-------|
| Default policy | ACCEPT (open) | DROP (closed) |
| External → Internal filtering | None | Forward chain with explicit allow/deny per service |
| Sensitive services (SMB, Redis, DICOM) | Accessible from external | Explicitly blocked at kernel level |
| SYN flood mitigation | Only after SIEM detection | Rate-limited at 50/s in kernel |
| Ban persistence | Lost on reboot | Ruleset persists via systemd; dynamic bans use timeout |
| Stateful tracking | None | ct state established/related/invalid |
| ICMP flood | Unmitigated | Rate-limited at 5/s |
| Log visibility | SIEM only | Kernel-level drop logs + SIEM |

---

## 9. Defense-in-Depth Layers

```
Layer 1: nftables          → Default-deny, stateful, rate-limiting (proactive)
Layer 2: Suricata IDS      → Signature-based detection, alert generation
Layer 3: SIEM auto-ban     → Behavioral detection, dynamic banning (reactive)
Layer 4: Vuln detector     → Exploit-specific detection (SMB, Redis, DICOM, HTTP, SSH, SMTP)
```

Each layer catches what the previous one misses. nftables blocks unauthorized traffic before it even reaches the detection engines. The SIEM catches malicious behavior on allowed ports and dynamically adds offenders to the nftables banned set.
