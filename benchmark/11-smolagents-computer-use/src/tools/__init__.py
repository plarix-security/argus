"""smolagents tools package."""

from .system import SYSTEM_TOOLS
from .files import FILE_TOOLS
from .web import WEB_TOOLS

ALL_TOOLS = SYSTEM_TOOLS + FILE_TOOLS + WEB_TOOLS
