"""CrewAI research crew entry point."""

import sys
from .crew import ResearchCrew


def main():
    if len(sys.argv) < 2:
        print("Usage: python -m src.main <research topic>")
        sys.exit(1)

    topic = " ".join(sys.argv[1:])
    crew = ResearchCrew()
    result = crew.run(topic)
    print(f"\nResult: {result}")


if __name__ == "__main__":
    main()
