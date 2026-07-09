# Contributing to Spooffe

We welcome contributions to Spooffe!

For general contribution and community guidelines, please see the [community repo](https://github.com/cyberark/community).

## Table of Contents

- [Development](#development)
- [Building](#building)
- [Testing](#testing)
- [Releases](#releases)
- [Contributing Workflow](#contributing-workflow)

## Development

### Prerequisites

| Requirement | Version |
|-------------|---------|
| Go | 1.21+ |
| Linux | For testing cgroup spoofing |
| SPIRE | For end-to-end testing |

### Project Structure

```
spooffe/
├── cmd/              # CLI commands
│   ├── agent/        # Agent API commands
│   ├── dump/         # SVID dumping commands
│   ├── list/         # Container discovery
│   └── server/       # Server API commands
├── extractor/        # Container discovery logic
├── pkg/              # Shared packages
├── spiffe/           # SPIFFE/SPIRE integration
├── utils/            # Utility functions
└── main.go           # Entry point
```

### IDE Setup

We recommend using GoLand or VS Code with the Go extension for development.

## Building

```bash
# Build for current platform (static)
make build

# Build for Linux AMD64
make build-linux

# Build for Linux ARM64
make build-linux-arm64

# Build all platforms
make build-all

# Build with debug symbols
make build-debug
```

## Testing

```bash
# Run all tests
make test

# Format code
make fmt

# Run linters
make lint
```

> **Note:** Full end-to-end testing requires a running SPIRE agent on a Kubernetes node.

## Releases

Releases are built and verified by the repository maintainers. To create a release:

1. Tag the commit: `git tag -a v1.0.0 -m "Release v1.0.0"`
2. Push the tag: `git push origin v1.0.0`
3. Build release binaries: `make build-all`

## Contributing Workflow

1. [Fork the project](https://help.github.com/en/github/getting-started-with-github/fork-a-repo)
2. [Clone your fork](https://help.github.com/en/github/creating-cloning-and-archiving-repositories/cloning-a-repository)
3. Create a feature branch: `git checkout -b feature/my-feature`
4. Make your changes and commit: `git commit -m "Add my feature"`
5. Run tests and linting: `make lint test`
6. [Push your changes](https://help.github.com/en/github/using-git/pushing-commits-to-a-remote-repository)
7. [Create a Pull Request](https://help.github.com/en/github/collaborating-with-issues-and-pull-requests/creating-a-pull-request-from-a-fork)

From here your pull request will be reviewed and once you've responded to all feedback, it will be merged into the project. Congratulations, you're a contributor!  


## Legal  
Any submission of work, including any issue, request, modification of, or addition to, an existing work ("Contribution") to "spooffe-main" shall be governed by and subject to the terms of the Apache License 2.0 (the "License") and to the following complementary terms. In case of any conflict or inconsistency between the provision of the License and the complementary terms, the complementary terms shall prevail. By submitting the Contribution, you represent and warrant that the Contribution is your original creation and you own all right, title and interest in the Contribution. You represent that you are legally entitled to grant the rights set out in the License and herein, without violation of, or conflict with, the rights of any other party. You represent that your Contribution includes complete details of any third-party license or other restriction associated with any part of your Contribution of which you are personally aware.
