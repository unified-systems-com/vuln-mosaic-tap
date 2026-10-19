"""Plugin validation-system tests (new-plugin skill, Step 9): structure and strict levels."""

from pathlib import Path

from tap_plugins.validate.service import validate_plugin

# The plugin PACKAGE directory, which resolves the same way from an editable checkout and
# from an installed wheel (`pytest --pyargs tap_plugin.vuln_mosaic`).
PLUGIN_ROOT = Path(__file__).resolve().parents[1]


class TestStructure:
    def test_structure_passes(self) -> None:
        result = validate_plugin(PLUGIN_ROOT, level="structure")
        if not result.ok:
            raise AssertionError(result.to_human())

    def test_strict_passes(self) -> None:
        result = validate_plugin(PLUGIN_ROOT, level="structure", strict=True)
        if not result.ok:
            raise AssertionError(result.to_human())
