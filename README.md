# Fusil Cereggii Plugin

This plugin provides specialized fuzzing support for the [cereggii](https://github.com/dpdani/cereggii) library.

## Features

- **Tricky Inputs**: Comprehensive collection of edge-case objects for cereggii types:
  - AtomicInt64 with boundary values
  - AtomicDict with hash collisions and malicious keys
  - Recursive structures
  - ThreadHandle instances
  - Weird subclasses

- **Scenario Mode**: High-contention fuzzing scenarios that stress-test cereggii's concurrency primitives

- **Argument Generators**: Automatically injects cereggii-specific inputs into generated fuzzing scripts

## Installation

```bash
pip install -e .
```

## Usage

### Standard API Fuzzing with Tricky Inputs

Fuzz cereggii's API with automatically-injected tricky objects:

```bash
fusil --modules=cereggii
```

The plugin will automatically activate and inject tricky AtomicInt64, AtomicDict, and other objects as arguments.

### Scenario Mode

Run high-contention concurrency scenarios:

```bash
fusil --modules=cereggii --fuzz-cereggii-scenarios
```

This mode runs specialized scenarios like:
- `scenario_numeric_hell`: Hammers atomic operations with boundary values
- `scenario_callback_hell`: Tests update methods with malicious callables
- And many more...

## Architecture

The plugin follows the fusil plugin API:

```
fusil_cereggii_plugin/
├── __init__.py                     # Plugin registration
├── tricky_cereggii_aggregator.py   # Aggregates all tricky modules
└── samples/                        # Tricky object definitions
    ├── tricky_atomicint64.py
    ├── tricky_atomicdict.py
    ├── tricky_atomicint_scenarios.py
    └── ...
```

## Development

To modify the tricky inputs or scenarios, edit files in `samples/`.

The aggregator will automatically:
- Read source code for embedding in generated scripts
- Extract object names for argument generators
- Collect scenario functions
    