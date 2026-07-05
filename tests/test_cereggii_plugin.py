"""Unit tests for the cereggii plugin's ``register()`` wiring and generated scenario runner.

Runtime-free: ``register()`` is driven against a stub PluginManager that records the ``add_*``
calls, so no fusil runtime stack is needed. The stub deliberately has **no**
``add_scenario_provider`` method -- if the plugin ever calls it again, these tests fail loudly
(the scenario-provider hook was removed from fusil; scenarios go through definitions + a mode).
The scenario-mode ``setup_script`` is exercised with a capturing fake writer to assert the
emitted runner discovers scenarios from ``globals()`` and never imports the plugin in the child.
"""

import unittest
from types import SimpleNamespace

from fusil_cereggii_plugin import register


class StubManager:
    """Records every registration call the plugin makes."""

    def __init__(self):
        self.cli_options = []
        self.argument_generators = []  # (func, category, weight, condition)
        self.definitions_providers = []
        self.fuzzing_modes = []  # (name, activation_check, setup_script)
        self.blacklist = []
        self.whitelist = []
        self.hooks = {}
        self.dependencies = []

    def add_cli_option(self, *args, **kwargs):
        self.cli_options.append((args, kwargs))

    def add_argument_generator(self, func, category, weight=1, condition=None):
        self.argument_generators.append((func, category, weight, condition))

    def add_definitions_provider(self, func):
        self.definitions_providers.append(func)

    def add_fuzzing_mode(self, name, activation_check, setup_script):
        self.fuzzing_modes.append((name, activation_check, setup_script))

    def add_blacklist_entry(self, kind, pattern, pattern_type="exact"):
        self.blacklist.append((kind, pattern, pattern_type))

    def add_whitelist_entry(self, kind, pattern, pattern_type="exact"):
        self.whitelist.append((kind, pattern, pattern_type))

    def add_hook(self, name, func):
        self.hooks.setdefault(name, []).append(func)

    def declare_dependency(self, name, required_version=None):
        self.dependencies.append(name)


class CaptureWriter:
    """Minimal WritePythonCode stand-in that records the emitted source."""

    def __init__(self):
        self.lines = []

    def write(self, level, text):
        self.lines.append(("    " * level) + text)

    def emptyLine(self):
        self.lines.append("")

    def write_print_to_stderr(self, level, expr):
        self.lines.append(("    " * level) + f"print({expr}, file=stderr)")

    def getvalue(self):
        return "\n".join(self.lines)


def _registered():
    m = StubManager()
    register(m)
    return m


class TestRegisterWiring(unittest.TestCase):
    def test_cli_option_added(self):
        m = _registered()
        flags = [args[0] for args, _ in m.cli_options]
        self.assertIn("--fuzz-cereggii-scenarios", flags)

    def test_argument_generators_registered_across_categories(self):
        m = _registered()
        self.assertEqual(len(m.argument_generators), 12)
        categories = {cat for _f, cat, _w, _c in m.argument_generators}
        self.assertEqual(categories, {"hashable", "simple", "complex"})

    def test_definitions_provider_and_mode(self):
        m = _registered()
        self.assertEqual(len(m.definitions_providers), 1)
        self.assertEqual([name for name, _a, _s in m.fuzzing_modes], ["cereggii_scenario"])

    def test_blacklist_whitelist_and_dependency(self):
        m = _registered()
        self.assertIn(("method", "_rehash", "exact"), m.blacklist)
        self.assertIn(("method", "wait", "exact"), m.blacklist)
        self.assertIn(("class", "*Test", "glob"), m.blacklist)
        self.assertIn(("method", "__del__", "exact"), m.whitelist)
        self.assertEqual(m.dependencies, ["cereggii"])
        self.assertIn("startup", m.hooks)

    def test_no_scenario_provider_is_called(self):
        # StubManager has no add_scenario_provider; register() completing proves the removed
        # hook is no longer used.
        self.assertFalse(hasattr(StubManager, "add_scenario_provider"))
        register(StubManager())  # must not raise AttributeError


class TestActivationCondition(unittest.TestCase):
    def _condition(self):
        m = _registered()
        return m.argument_generators[0][3]

    def test_active_for_cereggii_module(self):
        cond = self._condition()
        self.assertTrue(cond(SimpleNamespace(), "cereggii"))

    def test_inactive_for_other_module(self):
        cond = self._condition()
        self.assertFalse(cond(SimpleNamespace(fuzz_cereggii_scenarios=False), "json"))

    def test_active_when_scenario_flag_set(self):
        cond = self._condition()
        self.assertTrue(cond(SimpleNamespace(fuzz_cereggii_scenarios=True), "json"))


class TestDefinitionsProvider(unittest.TestCase):
    def test_returns_none_for_non_target(self):
        provider = _registered().definitions_providers[0]
        self.assertIsNone(provider(SimpleNamespace(fuzz_cereggii_scenarios=False), "json"))

    def test_returns_source_for_target(self):
        provider = _registered().definitions_providers[0]
        code = provider(SimpleNamespace(), "cereggii")
        self.assertIsNotNone(code)
        self.assertIn("BEGIN Tricky Cereggii Definitions", code)


class TestScenarioRunnerGeneration(unittest.TestCase):
    def _runner_source(self):
        _name, _activation, setup = _registered().fuzzing_modes[0]
        writer = CaptureWriter()
        setup(writer)
        return writer.getvalue()

    def test_runner_does_not_import_the_plugin_in_the_child(self):
        src = self._runner_source()
        # The critical fix: the fuzzed child must NOT import this plugin (it may run under a
        # --python that doesn't have it installed).
        self.assertNotIn("fusil_cereggii_plugin", src)
        self.assertNotIn("tricky_cereggii_aggregator", src)

    def test_runner_discovers_scenarios_from_globals(self):
        src = self._runner_source()
        self.assertIn("_cereggii_scenarios", src)
        self.assertIn("globals().get(_dict_name)", src)
        self.assertIn("choice(_all_scenario_names)", src)

    def test_activation_check_follows_flag(self):
        _name, activation, _setup = _registered().fuzzing_modes[0]
        self.assertTrue(activation(SimpleNamespace(fuzz_cereggii_scenarios=True)))
        self.assertFalse(activation(SimpleNamespace(fuzz_cereggii_scenarios=False)))


class TestArgumentGeneratorFallbacks(unittest.TestCase):
    """The per-type generators return a reference to a pre-built tricky object, or a safe
    fallback expression when the aggregator produced no instances."""

    def _gen(self, name):
        for func, _cat, _w, _c in _registered().argument_generators:
            if func.__name__ == name:
                return func
        raise AssertionError(f"generator {name} not registered")

    def test_atomicint64_uses_reference_or_fallback(self):
        import fusil_cereggii_plugin.tricky_cereggii_aggregator as agg

        gen = self._gen("gen_tricky_atomicint64")
        saved = agg.tricky_atomicint64_instance_names
        try:
            agg.tricky_atomicint64_instance_names = []
            self.assertEqual(gen(), ["cereggii.AtomicInt64(0)"])  # fallback
            agg.tricky_atomicint64_instance_names = ["boundary_max"]
            self.assertEqual(gen(), ["tricky_atomic_ints['boundary_max']"])  # reference
        finally:
            agg.tricky_atomicint64_instance_names = saved


if __name__ == "__main__":
    unittest.main()
