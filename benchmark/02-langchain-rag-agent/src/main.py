"""RAG agent entry point."""

import sys
from .agent import RAGAgent


def main():
    if len(sys.argv) < 2:
        print("Usage: python -m src.main <query>")
        sys.exit(1)

    query = " ".join(sys.argv[1:])
    agent = RAGAgent()
    result = agent.query(query)
    print(f"\nResult: {result}")


if __name__ == "__main__":
    main()
