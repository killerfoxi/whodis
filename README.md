# Hickory DNS Dynamic Update Client

A robust, idiomatic Rust tool for performing authenticated Dynamic DNS (DDNS) updates using SIG(0) encryption. Designed to work seamlessly with [Hickory DNS](https://github.com/hickory-dns/hickory-dns) (formerly Trust-DNS) and modern Linux networking stacks.

## Features

* **🔒 Secure:** Uses `RSASHA256` (SIG(0)) cryptographic signatures for all updates.
* **🛡️ Type-Safe:** Built with Rust, ensuring memory safety and correctness.
* **🚀 Zero-Cost Validation:** Validates your cryptographic keys at **compile time**. You cannot build a binary with an invalid key.
* **🌐 Dual Stack:** Intelligent support for IPv4 and IPv6 (`A` and `AAAA` records).
* **🤖 Automated:** Designed to hook into `networkd-dispatcher` for "set and forget" operation on link changes.

## Prerequisites

* Rust 1.75+ (Edition 2024 preferred)
* OpenSSL (for key generation)
* A running Hickory DNS server

## 1. Key Generation

This project expects a PEM-formatted RSA key named `dns_update.key` in the project root during compilation. This key is embedded into the binary for ease of deployment.

Generate the key pair:

```bash
# 1. Generate the Private Key (RSA 2048-bit)
openssl genrsa -out dns_update.key 2048

# 2. Extract the Public Key (Needed for the Server)
openssl rsa -in dns_update.key -pubout -out dns_update_pub.pem

```

> **Note:** The `dns_update.key` must be present in the root directory when you run `cargo build`. If the key is missing or invalid, the build will fail intentionally.

## 2. Server Configuration

Configure your Hickory DNS server to accept signed updates for your zone.

Add the following to your Hickory DNS configuration file (usually `/etc/named.toml`):

```toml
[[zones]]
zone = "dyn.lan"
zone_type = "Primary"

# The authentication key configuration
[[zones.keys]]
algorithm = "RSASHA256"
# This file should contain the key pair (or public key) allowing verification
key_path = "/etc/hickory/dns_update.key" 
purpose = "ZoneUpdateAuth"

[zones.stores]
type = "sqlite"
zone_file_path = "dyn.lan.zone"
journal_file_path = "dyn.lan_update.jrnl"
allow_update = true

```

Ensure the user running the Hickory DNS daemon has read permissions on `/etc/hickory/dns_update.key`.

## 3. Installation & Usage

### Build

```bash
cargo build --release
sudo cp target/release/whodis /usr/local/bin/

```

### Manual Usage

The tool attempts to auto-detect your IP address. You can also enforce specific modes or IP addresses.

```bash
# Update both IPv4 and IPv6 (Auto-detect)
whodis --zone dyn.lan --hostname laptop.dyn.lan --server 192.168.1.53:53

# Force IPv4 Only
whodis --zone dyn.lan --hostname laptop.dyn.lan --server 192.168.1.53:53 --mode v4-only

# Manually set a specific IP (Auto-detection skipped)
whodis --zone dyn.lan --hostname laptop.dyn.lan --server 192.168.1.53:53 --ip 10.0.50.100

```

**CLI Arguments:**

| Flag | Description | Default |
| --- | --- | --- |
| `-z, --zone` | The target DNS zone (e.g., `dyn.lan.`) | Required |
| `-n, --hostname` | The hostname record to update (e.g., `host.dyn.lan.`) | Required |
| `-s, --server` | The DNS server address (e.g., `192.168.1.1:53`) | Required |
| `-m, --mode` | Update mode: `v4-only`, `v6-only`, or `both` | `both` |
| `--ip` | Explicit IP address. Skips auto-detection. | Auto |

## 4. Automation (Systemd & Networkd)

To automatically update DNS whenever your network interface comes up or changes IP, integrate with `networkd-dispatcher`.

### A. The Service Unit

Create `/etc/systemd/system/dns-updater.service`:

```ini
[Unit]
Description=Whodis dynamic DNS update
Documentation=https://github.com/killerfoxi/whodis

[Service]
Type=oneshot
ExecStart=/usr/local/bin/whodis \
    --zone dyn.lan. \
    --hostname %H.dyn.lan. \
    --server 192.168.1.53:53 \
    --mode both
FailureAction=none

```

*(Note: `%H` automatically inserts the machine's hostname).*

### B. The Dispatcher Hook

Create `/etc/networkd-dispatcher/routable.d/50-dns-updater`:

```bash
#!/bin/bash
# Only run for physical interfaces or wlan, ignore docker/veth
if [[ "$IFACE" == "lo" ]] || [[ "$IFACE" == "docker"* ]]; then
    exit 0
fi

# Reload the service to trigger an update
systemctl restart --no-block dns-updater.service

```

Make it executable:

```bash
sudo chmod 755 /etc/networkd-dispatcher/routable.d/50-dns-updater

```

## Troubleshooting

**Build fails with "Missing Security Key"**

* Ensure `dns_update.key` exists in the project root (next to `Cargo.toml`).
* Ensure the key is a valid PEM RSA key.

**Server returns `Refused` or `SERVFAIL**`

* Check that the key in `/etc/hickory/dns_update.key` on the server matches the key used to build the client.
* Ensure the system clocks on the client and server are synchronized (signatures have timestamps).
* Verify the `zone` name in the arguments matches the `zone` in the server config exactly (trailing dots matter in some contexts, though this tool handles them).
