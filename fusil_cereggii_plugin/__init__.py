"""
Fusil Cereggii Plugin

This plugin provides specialized fuzzing support for the cereggii library,
including tricky inputs, scenarios, and a dedicated scenario-running mode.
"""

import pathlib
import sys
from random import choice

def register(manager):
    """
    Plugin registration function for the cereggii plugin.
    
    Args:
        manager: The PluginManager instance
    """
    print("[Cereggii Plugin] Registering cereggii plugin...")
    
    # Import aggregator (which imports all tricky modules)
    try:
        from . import tricky_cereggii_aggregator
    except ImportError as e:
        print(f"[Cereggii Plugin] ERROR: Failed to import aggregator: {e}", file=sys.stderr)
        return
    
    # 1. Add CLI options
    manager.add_cli_option(
        '--fuzz-cereggii-scenarios',
        help='Run only specialized cereggii fuzzing scenarios instead of general API fuzzing.',
        action='store_true',
        default=False,
    )
    
    # 2. Register argument generators for cereggii types
    
    def gen_tricky_atomicint64():
        """Generate a reference to a tricky AtomicInt64 instance."""
        if not tricky_cereggii_aggregator.tricky_atomicint64_instance_names:
            return ["cereggii.AtomicInt64(0)"]  # Fallback
        name = choice(tricky_cereggii_aggregator.tricky_atomicint64_instance_names)
        return [f"tricky_atomic_ints['{name}']"]
    
    def gen_tricky_atomicdict():
        """Generate a reference to a tricky AtomicDict instance."""
        if not tricky_cereggii_aggregator.tricky_atomicdict_instance_names:
            return ["cereggii.AtomicDict()"]  # Fallback
        name = choice(tricky_cereggii_aggregator.tricky_atomicdict_instance_names)
        return [f"tricky_atomic_dicts['{name}']"]
    
    def gen_tricky_weird_cereggii():
        """Generate a reference to a weird cereggii subclass instance."""
        if not tricky_cereggii_aggregator.tricky_weird_cereggii_instance_names:
            return ["object()"]  # Fallback
        name = choice(tricky_cereggii_aggregator.tricky_weird_cereggii_instance_names)
        return [f"tricky_weird_cereggii_objects['{name}']"]
    
    def gen_tricky_recursive_cereggii():
        """Generate a reference to a tricky recursive cereggii object."""
        if not tricky_cereggii_aggregator.tricky_recursive_object_names:
            return ["['recursive_fallback']"]  # Fallback
        name = choice(tricky_cereggii_aggregator.tricky_recursive_object_names)
        return [f"tricky_recursive_objects['{name}']"]
    
    def gen_tricky_threadhandle():
        """Generate a reference to a tricky ThreadHandle instance."""
        if not tricky_cereggii_aggregator.tricky_threadhandle_instance_names:
            return ["cereggii.ThreadHandle(None)"]  # Fallback
        name = choice(tricky_cereggii_aggregator.tricky_threadhandle_instance_names)
        return [f"tricky_threadhandle_collection['{name}']"]
    
    def gen_tricky_hashable_key_cereggii():
        """Generate a reference to a hashable cereggii key."""
        if not tricky_cereggii_aggregator.tricky_hashable_key_names:
            return ["'fallback_key'"]  # Fallback
        name = choice(tricky_cereggii_aggregator.tricky_hashable_key_names)
        return [f"tricky_hashable_keys['{name}']"]
    
    # Condition: only active when targeting cereggii
    def is_cereggii_target(config, module_name):
        return module_name == "cereggii" or getattr(config, 'fuzz_cereggii_scenarios', False)
    
    # Register generators with high weight to make them common for cereggii
    manager.add_argument_generator(gen_tricky_atomicint64, 'hashable', weight=10, condition=is_cereggii_target)
    manager.add_argument_generator(gen_tricky_hashable_key_cereggii, 'hashable', weight=10, condition=is_cereggii_target)
    
    manager.add_argument_generator(gen_tricky_atomicint64, 'simple', weight=10, condition=is_cereggii_target)
    manager.add_argument_generator(gen_tricky_weird_cereggii, 'simple', weight=10, condition=is_cereggii_target)
    manager.add_argument_generator(gen_tricky_recursive_cereggii, 'simple', weight=10, condition=is_cereggii_target)
    manager.add_argument_generator(gen_tricky_threadhandle, 'simple', weight=10, condition=is_cereggii_target)
    
    manager.add_argument_generator(gen_tricky_atomicdict, 'complex', weight=10, condition=is_cereggii_target)
    manager.add_argument_generator(gen_tricky_atomicint64, 'complex', weight=5, condition=is_cereggii_target)
    manager.add_argument_generator(gen_tricky_hashable_key_cereggii, 'complex', weight=5, condition=is_cereggii_target)
    manager.add_argument_generator(gen_tricky_weird_cereggii, 'complex', weight=5, condition=is_cereggii_target)
    manager.add_argument_generator(gen_tricky_recursive_cereggii, 'complex', weight=5, condition=is_cereggii_target)
    manager.add_argument_generator(gen_tricky_threadhandle, 'complex', weight=5, condition=is_cereggii_target)
    
    # 3. Register definitions provider
    
    def provide_cereggii_definitions(config, module_name):
        """Provide cereggii tricky object definitions."""
        if not is_cereggii_target(config, module_name):
            return None
        
        # Aggregate all code snippets
        all_code = []
        all_code.append("# --- BEGIN Tricky Cereggii Definitions ---")
        all_code.append('print("Embedding tricky cereggii code snippets...", file=stderr)')
        
        for name, code_snippet in tricky_cereggii_aggregator.tricky_cereggii_code_snippets.items():
            if code_snippet:
                origin_module = name.replace("_code", ".py")
                all_code.append(f"# --- Code from {origin_module} ---")
                all_code.append(code_snippet)
        
        all_code.append("# --- END Tricky Cereggii Definitions ---")
        return "\n".join(all_code)
    
    manager.add_definitions_provider(provide_cereggii_definitions)
    
    # 4. Register scenario provider
    
    def provide_cereggii_scenarios(config, module_name):
        """Provide cereggii scenarios."""
        if not is_cereggii_target(config, module_name):
            return None
        
        # Import scenario functions from aggregator
        # These should be available after importing the aggregator
        scenarios = {}
        
        # Collect all scenario functions
        # The aggregator exports lists of scenario names, not the functions themselves
        # We need to import them from their original modules
        # For now, return an empty dict - we'll implement this fully in the aggregator
        
        return scenarios  # Will be populated by aggregator
    
    manager.add_scenario_provider(provide_cereggii_scenarios)
    
    # 5. Register the cereggii scenario mode
    
    def is_scenario_mode_active(config):
        """Check if cereggii scenario mode should be active."""
        return getattr(config, 'fuzz_cereggii_scenarios', False)
    
    def setup_scenario_mode_script(write_python_code):
        """Generate the scenario runner code."""
        wpc = write_python_code  # Shorthand
        
        # Check if aggregator is available
        wpc.write(0, "# Cereggii Scenario Mode")
        wpc.write(0, f"from fusil_cereggii_plugin import tricky_cereggii_aggregator")
        wpc.emptyLine()
        
        # Get all scenario names
        wpc.write(0, "_all_scenario_names = []")
        scenario_sources = [
            "atomicint_scenario_names", "atomicref_scenario_names",
            "python_utils_scenario_names", "threadhandle_scenario_names",
            "stateful_scenario_names", "concurrency_hell_scenario_names",
            "synergy_scenario_names",
        ]
        
        for source_list_name in scenario_sources:
            wpc.write(0, f"if hasattr(tricky_cereggii_aggregator, '{source_list_name}'):")
            wpc.write(1, f"_all_scenario_names.extend(tricky_cereggii_aggregator.{source_list_name})")
        
        wpc.emptyLine()
        
        wpc.write(0, "if not _all_scenario_names:")
        wpc.write_print_to_stderr(1, '"ERROR: No cereggii scenarios found to run."')
        wpc.write(1, "sys.exit(1)")
        wpc.emptyLine()
        
        wpc.write_print_to_stderr(0, 'f"Found {len(_all_scenario_names)} cereggii scenarios."')
        wpc.emptyLine()
        
        # Run scenarios
        num_scenarios = 10  # Could be configurable
        wpc.write(0, f"for i in range({num_scenarios}):")
        wpc.write(1, "scenario_name = random.choice(_all_scenario_names)")
        wpc.write_print_to_stderr(1, f'f"\\n--- [{{i+1}}/{num_scenarios}] Running: {{scenario_name}} ---"')
        
        wpc.write(1, "try:")
        wpc.write(2, "_scenario_func = None")
        
        # Find the scenario function
        scenario_dicts = [
            "atomicint_scenarios", "atomicref_scenarios", "python_utils_scenarios",
            "threadhandle_scenarios", "stateful_scenarios", "concurrency_hell_scenarios",
            "synergy_scenarios",
        ]
        
        wpc.write(2, f"for _dict_name in {scenario_dicts}:")
        wpc.write(3, "_scenario_dict = globals().get(_dict_name)")
        wpc.write(3, "if _scenario_dict and scenario_name in _scenario_dict:")
        wpc.write(4, "_scenario_func = _scenario_dict[scenario_name]")
        wpc.write(4, "break")
        wpc.emptyLine()
        
        wpc.write(2, "if _scenario_func:")
        wpc.write(3, "_scenario_func()")
        wpc.write_print_to_stderr(3, 'f"--- Scenario {scenario_name} completed. ---"')
        wpc.write(2, "else:")
        wpc.write_print_to_stderr(3, 'f"ERROR: Could not find function for {scenario_name}"')
        
        wpc.write(1, "except Exception as e_scenario:")
        wpc.write_print_to_stderr(2, 'f"--- Scenario {scenario_name} FAILED: {type(e_scenario).__name__}: {e_scenario} ---"')
        
        wpc.write(1, "collect()  # GC between scenarios")
        wpc.emptyLine()
    
    manager.add_fuzzing_mode(
        name='cereggii_scenario',
        activation_check=is_scenario_mode_active,
        setup_script=setup_scenario_mode_script
    )
    
    # 6. Add hooks
    
    def cereggii_startup_hook(config):
        """Print startup message for cereggii plugin."""
        if is_scenario_mode_active(config) or config.modules == "cereggii":
            print("[Cereggii Plugin] Cereggii fuzzing support loaded", file=sys.stderr)
    
    manager.add_hook('startup', cereggii_startup_hook)
    
    print("[Cereggii Plugin] Registration complete!")
