"""
Fusil Cereggii Plugin

This plugin provides specialized fuzzing support for the cereggii library:
  * "tricky" input objects (AtomicInt64/AtomicDict/ThreadHandle/... with hostile values),
    injected as arguments into fuzzed calls via argument generators,
  * a definitions provider that embeds the tricky-object setup (and the scenario functions)
    into every generated script, and
  * a dedicated ``cereggii_scenario`` fuzzing mode that runs high-contention scenarios.

Scenarios reach the fuzzed child as *source* (via the definitions provider) and are run by the
mode's generated runner from the child's own ``globals()`` -- the plugin is never imported in
the child, so the mode works even when ``--python`` points at an interpreter without the plugin
installed.
"""

import sys
from random import choice

# The scenario-dict names the definitions provider embeds into the generated script's
# globals() (each tricky_*_scenarios module defines one of these dicts: name -> callable).
_SCENARIO_DICT_NAMES = [
    "atomicint_scenarios",
    "atomicref_scenarios",
    "python_utils_scenarios",
    "threadhandle_scenarios",
    "stateful_scenarios",
    "concurrency_hell_scenarios",
    "synergy_scenarios",
]


def register(manager):
    """Plugin registration function for the cereggii plugin (``fusil.plugins`` group)."""
    print("[Cereggii Plugin] Registering cereggii plugin...")

    # Blacklist internal methods that cause uninteresting crashes / hangs.
    manager.add_blacklist_entry("method", "_rehash")  # internal C method
    manager.add_blacklist_entry("method", "wait")  # blocking method

    # Blacklist test-related classes using glob patterns.
    manager.add_blacklist_entry("class", "*Test", pattern_type="glob")
    manager.add_blacklist_entry("class", "*TestCase", pattern_type="glob")

    manager.add_whitelist_entry("method", "__del__")

    # Import aggregator (which imports all tricky modules).
    try:
        from . import tricky_cereggii_aggregator
    except ImportError as e:
        print(f"[Cereggii Plugin] ERROR: Failed to import aggregator: {e}", file=sys.stderr)
        return

    # Advertise the cereggii dependency (advisory; the aggregator import above is the hard gate).
    manager.declare_dependency("cereggii")

    # 1. Add CLI options.
    manager.add_cli_option(
        "--fuzz-cereggii-scenarios",
        help="Run only specialized cereggii fuzzing scenarios instead of general API fuzzing.",
        action="store_true",
        default=False,
    )

    # 2. Register argument generators for cereggii types.

    def gen_tricky_atomicint64():
        """Generate a reference to a tricky AtomicInt64 instance."""
        if not tricky_cereggii_aggregator.tricky_atomicint64_instance_names:
            return ["cereggii.AtomicInt64(0)"]  # fallback
        name = choice(tricky_cereggii_aggregator.tricky_atomicint64_instance_names)
        return [f"tricky_atomic_ints['{name}']"]

    def gen_tricky_atomicdict():
        """Generate a reference to a tricky AtomicDict instance."""
        if not tricky_cereggii_aggregator.tricky_atomicdict_instance_names:
            return ["cereggii.AtomicDict()"]  # fallback
        name = choice(tricky_cereggii_aggregator.tricky_atomicdict_instance_names)
        return [f"tricky_atomic_dicts['{name}']"]

    def gen_tricky_weird_cereggii():
        """Generate a reference to a weird cereggii subclass instance."""
        if not tricky_cereggii_aggregator.tricky_weird_cereggii_instance_names:
            return ["object()"]  # fallback
        name = choice(tricky_cereggii_aggregator.tricky_weird_cereggii_instance_names)
        return [f"tricky_weird_cereggii_objects['{name}']"]

    def gen_tricky_recursive_cereggii():
        """Generate a reference to a tricky recursive cereggii object."""
        if not tricky_cereggii_aggregator.tricky_recursive_object_names:
            return ["['recursive_fallback']"]  # fallback
        name = choice(tricky_cereggii_aggregator.tricky_recursive_object_names)
        return [f"tricky_recursive_objects['{name}']"]

    def gen_tricky_threadhandle():
        """Generate a reference to a tricky ThreadHandle instance."""
        if not tricky_cereggii_aggregator.tricky_threadhandle_instance_names:
            return ["cereggii.ThreadHandle(None)"]  # fallback
        name = choice(tricky_cereggii_aggregator.tricky_threadhandle_instance_names)
        return [f"tricky_threadhandle_collection['{name}']"]

    def gen_tricky_hashable_key_cereggii():
        """Generate a reference to a hashable cereggii key."""
        if not tricky_cereggii_aggregator.tricky_hashable_key_names:
            return ["'fallback_key'"]  # fallback
        name = choice(tricky_cereggii_aggregator.tricky_hashable_key_names)
        return [f"tricky_hashable_keys['{name}']"]

    # Condition: only active when targeting cereggii.
    def is_cereggii_target(config, module_name):
        return module_name == "cereggii" or getattr(config, "fuzz_cereggii_scenarios", False)

    # Register generators with high weight to make them common for cereggii.
    manager.add_argument_generator(
        gen_tricky_atomicint64, "hashable", weight=10, condition=is_cereggii_target
    )
    manager.add_argument_generator(
        gen_tricky_hashable_key_cereggii, "hashable", weight=10, condition=is_cereggii_target
    )

    manager.add_argument_generator(
        gen_tricky_atomicint64, "simple", weight=10, condition=is_cereggii_target
    )
    manager.add_argument_generator(
        gen_tricky_weird_cereggii, "simple", weight=10, condition=is_cereggii_target
    )
    manager.add_argument_generator(
        gen_tricky_recursive_cereggii, "simple", weight=10, condition=is_cereggii_target
    )
    manager.add_argument_generator(
        gen_tricky_threadhandle, "simple", weight=10, condition=is_cereggii_target
    )

    manager.add_argument_generator(
        gen_tricky_atomicdict, "complex", weight=10, condition=is_cereggii_target
    )
    manager.add_argument_generator(
        gen_tricky_atomicint64, "complex", weight=5, condition=is_cereggii_target
    )
    manager.add_argument_generator(
        gen_tricky_hashable_key_cereggii, "complex", weight=5, condition=is_cereggii_target
    )
    manager.add_argument_generator(
        gen_tricky_weird_cereggii, "complex", weight=5, condition=is_cereggii_target
    )
    manager.add_argument_generator(
        gen_tricky_recursive_cereggii, "complex", weight=5, condition=is_cereggii_target
    )
    manager.add_argument_generator(
        gen_tricky_threadhandle, "complex", weight=5, condition=is_cereggii_target
    )

    # 3. Register definitions provider (embeds the tricky-object + scenario source).

    def provide_cereggii_definitions(config, module_name):
        """Provide cereggii tricky object + scenario definitions."""
        if not is_cereggii_target(config, module_name):
            return None

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

    # 4. Register the cereggii scenario mode.
    #
    # NOTE: scenarios are not a separate plugin hook -- the scenario *functions* are embedded
    # by the definitions provider above (so they live in the generated script's globals()), and
    # this mode emits a runner that discovers and calls them from globals(). The runner does NOT
    # import this plugin: the fuzzed child (``--python``) may not have it installed.

    def is_scenario_mode_active(config):
        return getattr(config, "fuzz_cereggii_scenarios", False)

    def setup_scenario_mode_script(write_python_code):
        """Generate the scenario-runner main logic."""
        wpc = write_python_code
        num_scenarios = 10

        wpc.write(0, "# --- Cereggii Scenario Mode ---")
        # Collect every embedded scenario dict (name -> callable) from this script's globals().
        wpc.write(0, "_cereggii_scenarios = {}")
        wpc.write(0, f"for _dict_name in {_SCENARIO_DICT_NAMES!r}:")
        wpc.write(1, "_d = globals().get(_dict_name)")
        wpc.write(1, "if isinstance(_d, dict):")
        wpc.write(2, "_cereggii_scenarios.update(_d)")
        wpc.emptyLine()

        wpc.write(0, "_all_scenario_names = list(_cereggii_scenarios)")
        wpc.write(0, "if not _all_scenario_names:")
        wpc.write_print_to_stderr(1, '"ERROR: No cereggii scenarios found to run."')
        wpc.write(1, "sys.exit(1)")
        wpc.emptyLine()

        wpc.write_print_to_stderr(0, 'f"Found {len(_all_scenario_names)} cereggii scenarios."')
        wpc.emptyLine()

        wpc.write(0, f"for _i in range({num_scenarios}):")
        wpc.write(1, "scenario_name = choice(_all_scenario_names)")
        wpc.write_print_to_stderr(
            1, 'f"\\n--- [{_i + 1}/' + str(num_scenarios) + '] Running: {scenario_name} ---"'
        )
        wpc.write(1, "try:")
        wpc.write(2, "_cereggii_scenarios[scenario_name]()")
        wpc.write_print_to_stderr(2, 'f"--- Scenario {scenario_name} completed. ---"')
        wpc.write(1, "except Exception as _e_scenario:")
        wpc.write_print_to_stderr(
            2,
            'f"--- Scenario {scenario_name} FAILED: '
            '{type(_e_scenario).__name__}: {_e_scenario} ---"',
        )
        wpc.write(1, "collect()  # GC between scenarios")
        wpc.emptyLine()

    manager.add_fuzzing_mode(
        name="cereggii_scenario",
        activation_check=is_scenario_mode_active,
        setup_script=setup_scenario_mode_script,
    )

    # 5. Hooks.
    def cereggii_startup_hook(config):
        if is_scenario_mode_active(config) or "cereggii" in (getattr(config, "modules", "") or ""):
            print("[Cereggii Plugin] Cereggii fuzzing support loaded", file=sys.stderr)

    manager.add_hook("startup", cereggii_startup_hook)

    print("[Cereggii Plugin] Registration complete!")
