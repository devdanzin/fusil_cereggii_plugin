"""
Cereggii Aggregator for Fusil Plugin

This module imports all specialized cereggii tricky modules and aggregates
their source code, object names, and scenario names for use by the plugin.
"""

import pathlib
import sys
import importlib


def _read_module_source(module_path: pathlib.Path) -> str | None:
    """Reads the source code of a module file."""
    try:
        source_code = module_path.read_text(encoding='utf-8')
        print(f"[Cereggii Plugin] Successfully read source: {module_path.name}", file=sys.stderr)
        return source_code
    except FileNotFoundError:
        print(f"[Cereggii Plugin] ERROR: File not found: {module_path}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"[Cereggii Plugin] ERROR reading {module_path}: {e}", file=sys.stderr)
        return None


def _try_import_and_get_attribute(module_name: str, attribute_name: str) -> object | None:
    """Imports a module and safely retrieves an attribute."""
    try:
        # Import from the samples directory
        full_module_name = f"fusil_cereggii_plugin.samples.{module_name}"
        module = importlib.import_module(full_module_name)
    except ImportError as e:
        print(f"[Cereggii Plugin] ERROR importing {module_name}: {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"[Cereggii Plugin] ERROR with {module_name}: {e}", file=sys.stderr)
        return None
    
    try:
        attribute = getattr(module, attribute_name)
        return attribute
    except AttributeError:
        print(f"[Cereggii Plugin] ERROR: '{attribute_name}' not found in {module_name}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"[Cereggii Plugin] ERROR getting '{attribute_name}': {e}", file=sys.stderr)
        return None


# --- Aggregate Source Code ---

# List of all tricky modules
_MODULE_NAMES = [
    "tricky_atomicint64",
    "tricky_atomicdict",
    "tricky_recursive_cereggii",
    "tricky_colliding_keys",
    "tricky_weird_cereggii",
    "tricky_threadhandle",
    "tricky_atomicint_scenarios",
    "tricky_atomicref_scenarios",
    "tricky_python_utils_scenarios",
    "tricky_threadhandle_scenarios",
    "tricky_stateful_scenarios",
    "tricky_concurrency_hell",
    "tricky_synergy_scenarios",
    "tricky_reduce_nightmares",
]

# Get the directory where the samples are
_SAMPLES_DIR = pathlib.Path(__file__).parent / "samples"

# Dictionary to hold source code
tricky_cereggii_code_snippets = {}

print("\n[Cereggii Plugin] --- Aggregating Code Snippets ---", file=sys.stderr)
for name in _MODULE_NAMES:
    module_path = _SAMPLES_DIR / f"{name}.py"
    code = _read_module_source(module_path)
    tricky_cereggii_code_snippets[f"{name}_code"] = code

print(f"[Cereggii Plugin] Finished aggregating code snippets.", file=sys.stderr)


# --- Aggregate Object and Scenario Names ---

# Initialize lists to hold names
tricky_atomicint64_instance_names: list[str] = []
tricky_atomicdict_instance_names: list[str] = []
tricky_hashable_key_names: list[str] = []
tricky_recursive_object_names: list[str] = []
tricky_weird_cereggii_instance_names: list[str] = []
tricky_threadhandle_instance_names: list[str] = []
atomicint_scenario_names: list[str] = []
atomicref_scenario_names: list[str] = []
python_utils_scenario_names: list[str] = []
threadhandle_scenario_names: list[str] = []
stateful_scenario_names: list[str] = []
concurrency_hell_scenario_names: list[str] = []
synergy_scenario_names: list[str] = []

# Special variables that are dict/collection names, not lists of names
colliding_key_sets_name: str | None = None
reduce_nightmares_collection_name: str | None = None

# Map module names to what they export
_EXPORT_MAP = {
    "tricky_atomicint64": [
        ("tricky_atomic_ints", tricky_atomicint64_instance_names, 'dict_keys')
    ],
    "tricky_atomicdict": [
        ("tricky_hashable_keys", tricky_hashable_key_names, 'dict_keys'),
        ("tricky_atomic_dicts", tricky_atomicdict_instance_names, 'dict_keys'),
    ],
    "tricky_recursive_cereggii": [
        ("tricky_recursive_objects", tricky_recursive_object_names, 'dict_keys')
    ],
    "tricky_colliding_keys": [
        ("colliding_key_sets", "colliding_key_sets", 'var_name')
    ],
    "tricky_weird_cereggii": [
        ("tricky_weird_cereggii_objects", tricky_weird_cereggii_instance_names, 'dict_keys')
    ],
    "tricky_threadhandle": [
        ("tricky_threadhandle_collection", tricky_threadhandle_instance_names, 'dict_keys')
    ],
    "tricky_atomicint_scenarios": [
        ("atomicint_scenarios", atomicint_scenario_names, 'dict_keys')
    ],
    "tricky_atomicref_scenarios": [
        ("atomicref_scenarios", atomicref_scenario_names, 'dict_keys')
    ],
    "tricky_python_utils_scenarios": [
        ("python_utils_scenarios", python_utils_scenario_names, 'dict_keys')
    ],
    "tricky_threadhandle_scenarios": [
        ("threadhandle_scenarios", threadhandle_scenario_names, 'dict_keys')
    ],
    "tricky_stateful_scenarios": [
        ("stateful_scenarios", stateful_scenario_names, 'dict_keys')
    ],
    "tricky_concurrency_hell": [
        ("concurrency_hell_scenarios", concurrency_hell_scenario_names, 'dict_keys')
    ],
    "tricky_synergy_scenarios": [
        ("synergy_scenarios", synergy_scenario_names, 'dict_keys')
    ],
    "tricky_reduce_nightmares": [
        ("reduce_nightmares_collection", "reduce_nightmares_collection", 'var_name')
    ],
}

print("\n[Cereggii Plugin] --- Aggregating Object and Scenario Names ---", file=sys.stderr)
for module_name, exports in _EXPORT_MAP.items():
    for attr_name, target_var_or_list, extraction_type in exports:
        attribute_value = _try_import_and_get_attribute(module_name, attr_name)
        
        if attribute_value is not None:
            try:
                if extraction_type == 'dict_keys':
                    if isinstance(attribute_value, dict):
                        target_var_or_list.extend(list(attribute_value.keys()))
                        print(f"  [Cereggii Plugin] + Aggregated {len(list(attribute_value.keys()))} names from {module_name}.{attr_name}", file=sys.stderr)
                    else:
                        print(f"  [Cereggii Plugin] - WARNING: Expected dict for '{attr_name}', got {type(attribute_value)}", file=sys.stderr)
                        
                elif extraction_type == 'var_name':
                    # Store the variable name as a string
                    if target_var_or_list == "colliding_key_sets":
                        colliding_key_sets_name = attr_name
                    elif target_var_or_list == "reduce_nightmares_collection":
                        reduce_nightmares_collection_name = attr_name
                    print(f"  [Cereggii Plugin] + Exported variable name '{attr_name}' as '{target_var_or_list}'", file=sys.stderr)
                    
            except Exception as e:
                print(f"  [Cereggii Plugin] - ERROR processing {module_name}.{attr_name}: {e}", file=sys.stderr)
        else:
            print(f"  [Cereggii Plugin] - Failed to retrieve {module_name}.{attr_name}", file=sys.stderr)

print("[Cereggii Plugin] Finished aggregating names.", file=sys.stderr)


# --- Final Summary ---
print("\n[Cereggii Plugin] --- Aggregation Summary ---", file=sys.stderr)
loaded_snippets = sum(1 for code in tricky_cereggii_code_snippets.values() if code is not None)
print(f"[Cereggii Plugin] Code Snippets: {loaded_snippets}/{len(_MODULE_NAMES)}", file=sys.stderr)
print(f"[Cereggii Plugin] AtomicInt64 Instances: {len(tricky_atomicint64_instance_names)}", file=sys.stderr)
print(f"[Cereggii Plugin] AtomicDict Instances: {len(tricky_atomicdict_instance_names)}", file=sys.stderr)
print(f"[Cereggii Plugin] Hashable Keys: {len(tricky_hashable_key_names)}", file=sys.stderr)
print(f"[Cereggii Plugin] Recursive Objects: {len(tricky_recursive_object_names)}", file=sys.stderr)
print(f"[Cereggii Plugin] Weird Cereggii: {len(tricky_weird_cereggii_instance_names)}", file=sys.stderr)
print(f"[Cereggii Plugin] ThreadHandle: {len(tricky_threadhandle_instance_names)}", file=sys.stderr)
print(f"[Cereggii Plugin] AtomicInt Scenarios: {len(atomicint_scenario_names)}", file=sys.stderr)
print(f"[Cereggii Plugin] AtomicRef Scenarios: {len(atomicref_scenario_names)}", file=sys.stderr)
print(f"[Cereggii Plugin] Python Utils Scenarios: {len(python_utils_scenario_names)}", file=sys.stderr)
print(f"[Cereggii Plugin] ThreadHandle Scenarios: {len(threadhandle_scenario_names)}", file=sys.stderr)
print(f"[Cereggii Plugin] Stateful Scenarios: {len(stateful_scenario_names)}", file=sys.stderr)
print(f"[Cereggii Plugin] Concurrency Hell: {len(concurrency_hell_scenario_names)}", file=sys.stderr)
print(f"[Cereggii Plugin] Synergy Scenarios: {len(synergy_scenario_names)}", file=sys.stderr)
print("-" * 50, file=sys.stderr)
