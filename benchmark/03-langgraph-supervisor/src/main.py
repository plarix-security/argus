"""Supervisor system entry point."""

import sys
from .graph import SupervisorSystem


def main():
    if len(sys.argv) < 2:
        print("Usage: python -m src.main <task>")
        sys.exit(1)

    task = " ".join(sys.argv[1:])
    system = SupervisorSystem()
    result = system.run(task)
    print(f"\nResult: {result}")


if __name__ == "__main__":
    main()
