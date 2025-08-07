#!/usr/bin/env python3
"""Test runner script for Splurge Key Custodian."""

import sys
import subprocess
from pathlib import Path
from typing import List


def run_pytest(test_paths: List[str], additional_args: List[str] = None) -> int:
    """Run pytest with the specified test paths and arguments."""
    if additional_args is None:
        additional_args = []
    
    # Get the project root directory (parent of tests/)
    project_root = Path(__file__).parent.parent
    
    # Base pytest arguments
    base_args = [
        "pytest",
        "-v",  # Verbose mode
        "-x",  # Fail fast
        "--cov=splurge_key_custodian",
        "--cov-report=term-missing",
        "--cov-report=html",
    ]
    
    # Combine base args, test paths, and additional args
    cmd = base_args + test_paths + additional_args
    
    print(f"Running: {' '.join(cmd)}")
    print("-" * 80)
    
    try:
        # Change to project root directory before running pytest
        result = subprocess.run(cmd, check=False, cwd=project_root)
        return result.returncode
    except FileNotFoundError:
        print("Error: pytest not found. Please install pytest and pytest-cov:")
        print("  pip install pytest pytest-cov")
        return 1


def main() -> int:
    """Main function to run tests based on command line arguments."""
    if len(sys.argv) < 2:
        command = "all"
    else:
        command = sys.argv[1].lower()
    
    # Additional arguments passed to pytest
    additional_args = sys.argv[2:] if len(sys.argv) > 2 else []
    
    # Get the project root directory (parent of tests/)
    project_root = Path(__file__).parent.parent
    test_dir = project_root / "tests"
    
    if command == "all":
        print("Running all tests in order: unit, functional, integration...")
        
        # Run tests in specific order: unit, functional, integration
        test_order = [
            ("unit", str(test_dir / "unit")),
            ("functional", str(test_dir / "functional")),
            ("integration", str(test_dir / "integration"))
        ]
        
        total_exit_code = 0
        
        for test_type, test_path in test_order:
            print(f"\n{'='*20} Running {test_type.upper()} tests {'='*20}")
            exit_code = run_pytest([test_path], additional_args)
            if exit_code != 0:
                total_exit_code = exit_code
                print(f"\n{test_type.upper()} tests failed with exit code {exit_code}")
                # Continue with other test types even if one fails
        
        if total_exit_code == 0:
            print(f"\n{'='*20} All test types completed successfully {'='*20}")
        else:
            print(f"\n{'='*20} Some test types failed {'='*20}")
        
        return total_exit_code
    
    elif command == "unit":
        print("Running unit tests...")
        return run_pytest([str(test_dir / "unit")], additional_args)
    
    elif command == "integration":
        print("Running integration tests...")
        return run_pytest([str(test_dir / "integration")], additional_args)
    
    elif command == "functional":
        print("Running functional tests...")
        return run_pytest([str(test_dir / "functional")], additional_args)
    
    elif command == "help" or command == "-h" or command == "--help":
        print("Splurge Key Custodian Test Runner")
        print("=" * 40)
        print()
        print("Usage:")
        print("  python tests/run_tests.py [command] [additional_pytest_args...]")
        print()
        print("Commands:")
        print("  all          Run all tests (default)")
        print("  unit         Run unit tests only")
        print("  integration  Run integration tests only")
        print("  functional   Run functional tests only")
        print("  help         Show this help message")
        print()
        print("Examples:")
        print("  python tests/run_tests.py")
        print("  python tests/run_tests.py unit")
        print("  python tests/run_tests.py integration -k 'test_key_custodian'")
        print("  python tests/run_tests.py functional --tb=short")
        print()
        print("All test runs include:")
        print("  - pytest-cov with HTML report")
        print("  - Verbose mode (-v)")
        print("  - Fail fast (-x)")
        return 0
    
    else:
        print(f"Error: Unknown command '{command}'")
        print("Use 'python run_tests.py help' for usage information")
        return 1


if __name__ == "__main__":
    sys.exit(main()) 