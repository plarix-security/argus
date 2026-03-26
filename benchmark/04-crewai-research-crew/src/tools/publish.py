"""Article publishing tool."""

import os
from pathlib import Path
from crewai.tools import tool

OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "./output"))


@tool
def publish_article(title: str, content: str) -> str:
    """Publish an article to the output directory.

    Args:
        title: Article title
        content: Article content

    Returns:
        Confirmation with path
    """
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    safe_title = "".join(c if c.isalnum() or c in "-_" else "_" for c in title)
    output_path = OUTPUT_DIR / f"{safe_title}.md"

    # AFB04 WARNING: File write
    output_path.write_text(f"# {title}\n\n{content}")
    return f"Published to {output_path}"
