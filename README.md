![Tests](https://github.com/wayne-csrs/pySigma-backend-signals/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/wayne-csrs/2c405b5ce1eae6e116e72f3828760f37/raw/wayne-csrs-pySigma-backend-signals.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

# pySigma Signals Backend

A [pySigma](https://github.com/SigmaHQ/pySigma) backend for converting Sigma rules into Tanium Signals query syntax.

## Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Processing Pipeline](#processing-pipeline)
- [Maintainer](#maintainer)
- [Contributing](#contributing)
- [License](#license)

## Overview

This package provides:

- **Backend**: `sigma.backends.signals` with `SignalsBackend`
- **Pipeline**: `sigma.pipelines.signals` with `signals_pipeline`
- **Output format**: `default` (plain Signals query output)

The backend is designed for Sigma rule conversion with field normalisation that maps common Windows/Sysmon-style fields to Signals fields.

## Key Features

- Supports common Sigma condition patterns (`AND`, `OR`, list values, regex, CIDR expansion)
- Includes correlation query templates (event count, value count, temporal, temporal ordered)
- Provides category-specific field mappings through a dedicated processing pipeline
- Works in Python workflows and can be used with `sigma-cli` where backend discovery is configured

## Quick Start

Install dependencies (example with `pip`):

```bash
pip install pysigma
```

Then install this backend from source:

```bash
git clone https://github.com/wayne-csrs/pySigma-backend-signals.git
cd pySigma-backend-signals
pip install .
```

## Usage

### Python Example

```python
from sigma.collection import SigmaCollection
from sigma.backends.signals import SignalsBackend

rule = SigmaCollection.from_yaml(
    """
    title: Suspicious CommandLine
    status: test
    logsource:
      category: process_creation
      product: windows
    detection:
      sel:
        CommandLine|contains: mimikatz
      condition: sel
    """
)

backend = SignalsBackend()
queries = backend.convert(rule)
print(queries[0])
```

### sigma-cli Example

If your `sigma-cli` environment is set up to discover installed backends, you can run:

```bash
sigma convert -t signals -p signals path/to/rule.yml
```

## Processing Pipeline

The built-in `signals_pipeline` applies:

- Generic mappings for user/logon-related fields
- Category-aware mappings for:
  - Windows: `process_creation`, `image_load`, `file_event`, `network_connection`, `registry_event`, `registry_set`
  - Linux: `process_creation`, `network_connection`, `file_create`
  - macOS: `process_creation`, `file_create`

Examples of normalised fields include:

- `Image` -> `process.path`
- `CommandLine` -> `process.command_line`
- `TargetFilename` -> `file.path`
- `SourceIp` -> `network.source.ip`
- `RegistryValueData` -> `registry.value.data`

## Maintainer

- [Wayne Silva](https://github.com/wayne-csrs)

## Contributing

Contributions are welcome, especially for:

- Additional field mappings
- More rule category coverage
- Backend behavior tests and correlation test coverage

Please open an issue or submit a pull request.

## License

Licensed under **LGPL-3.0-only**. See [LICENSE](LICENSE).