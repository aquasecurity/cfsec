---
title: Installation
subtitle: Installing cfsec on your local machine
author: cfsec
tags: [installation, quickstart]
redirect_from:
- /docs/home/
---

> cfsec is in early access stage, it is not advised to rely on it for a production workload.

<!-- Install with brew/linuxbrew:

```cmd
brew install cfsec
```

Install with Chocolatey:

```cmd
choco install cfsec
``` -->

You can grab the binary for your system from the [releases page](https://github.com/aquasecurity/cfsec/releases).

Alternatively, install with Go:

```cmd
go install github.com/aquasecurity/cfsec/cmd/cfsec@latest
```

## Usage

cfsec will scan the specified directory. If no directory is specified, the current working directory will be used.

The exit status will be non-zero if cfsec finds problems, otherwise the exit status will be zero.

```cmd
cfsec .
```
<!-- 
## Use with Docker

As an alternative to installing and running cfsec on your system, you may
run cfsec in a Docker container.

To run:

```cmd
docker run --rm -it -v "$(pwd):/src" aquasec/cfsec /src
```
 -->
