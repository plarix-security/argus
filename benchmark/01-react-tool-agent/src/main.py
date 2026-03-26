"""ReAct agent entry point."""

import sys
from .agent import ReactAgent


def main():
    if len(sys.argv) < 2:
        print("Usage: python -m src.main <task>")
        print('Example: python -m src.main "What is 2+2?"')
        sys.exit(1)

    task = " ".join(sys.argv[1:])
    agent = ReactAgent()
    result = agent.run(task)
    print(f"\nFinal Result: {result}")


if __name__ == "__main__":
    main()
