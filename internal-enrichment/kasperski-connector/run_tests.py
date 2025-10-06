# run_tests.py - Script pour exécuter les tests
# !/usr/bin/env python3
"""Script to run Kaspersky connector tests"""

import sys
import subprocess
import os


def run_command(command, description):
    """Run a command and handle errors"""
    print(f"\n{'=' * 50}")
    print(f"Running: {description}")
    print(f"Command: {command}")
    print(f"{'=' * 50}")

    result = subprocess.run(command, shell=True, capture_output=True, text=True)

    if result.returncode == 0:
        print(f"✅ {description} passed")
        if result.stdout:
            print("Output:", result.stdout)
    else:
        print(f"❌ {description} failed")
        if result.stderr:
            print("Error:", result.stderr)
        if result.stdout:
            print("Output:", result.stdout)
        return False
    return True


def main():
    """Main test runner"""
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    print("🧪 Starting Kaspersky Connector Tests")

    tests = [
        ("pip install -r test_requirements.txt", "Installing test dependencies"),
        ("pytest tests/test_kaspersky_connector.py::TestKasperskyConnector::test_config_loader_valid -v",
         "Config validation test"),
        ("pytest tests/test_kaspersky_connector.py::TestKasperskyConnector::test_entity_in_scope_valid_file -v",
         "Scope validation test"),
        ("pytest tests/test_kaspersky_connector.py::TestConnectorClient::test_get_file_reputation_success -v",
         "API client test"),
        ("pytest tests/test_kaspersky_connector.py::TestConverterToStix::test_create_note_with_full_data -v",
         "STIX converter test"),
        ("pytest tests/ -v", "All tests"),
    ]

    failed_tests = []

    for command, description in tests:
        if not run_command(command, description):
            failed_tests.append(description)

    print(f"\n{'=' * 60}")
    print("📊 TEST SUMMARY")
    print(f"{'=' * 60}")

    if failed_tests:
        print(f"❌ {len(failed_tests)} test(s) failed:")
        for test in failed_tests:
            print(f"   - {test}")
        sys.exit(1)
    else:
        print("✅ All tests passed!")
        print("\n🎉 Kaspersky Connector is ready for deployment!")


if __name__ == "__main__":
    main()