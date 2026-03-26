"""ReAct agent implementation using OpenAI SDK."""

import os
import json
from typing import Any
from dotenv import load_dotenv
from openai import OpenAI

from .tools.calculator import calculate, calculate_subprocess, CALCULATOR_TOOLS
from .tools.file_writer import write_file, read_file, list_files, FILE_TOOLS
from .tools.web_search import web_search, WEB_SEARCH_TOOLS
from .tools.safe_calculator import safe_calculate, SAFE_CALCULATOR_TOOLS

load_dotenv()


class ReactAgent:
    """ReAct-pattern agent using OpenAI function calling."""

    def __init__(self):
        self.client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        self.model = "gpt-4o"
        self.max_turns = int(os.getenv("MAX_TURNS", "10"))
        self.debug = os.getenv("DEBUG", "false").lower() == "true"

        # All available tools
        self.tools = CALCULATOR_TOOLS + FILE_TOOLS + WEB_SEARCH_TOOLS + SAFE_CALCULATOR_TOOLS

        # Tool function mapping
        self.tool_functions = {
            "calculate": calculate,
            "calculate_subprocess": calculate_subprocess,
            "write_file": write_file,
            "read_file": read_file,
            "list_files": list_files,
            "web_search": web_search,
            "safe_calculate": safe_calculate,
        }

    def run(self, task: str) -> str:
        """Execute the ReAct loop for a given task."""
        messages = [
            {
                "role": "system",
                "content": (
                    "You are a helpful assistant that can search the web, perform calculations, "
                    "and read/write files. Use the available tools to complete the user's task. "
                    "Think step by step and use tools as needed."
                ),
            },
            {"role": "user", "content": task},
        ]

        for turn in range(self.max_turns):
            if self.debug:
                print(f"\n[Turn {turn + 1}/{self.max_turns}]")

            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                tools=self.tools,
                tool_choice="auto",
            )

            assistant_message = response.choices[0].message
            messages.append(assistant_message)

            # Check if we're done (no tool calls)
            if not assistant_message.tool_calls:
                return assistant_message.content or "Task completed."

            # Execute tool calls
            for tool_call in assistant_message.tool_calls:
                function_name = tool_call.function.name
                arguments = json.loads(tool_call.function.arguments)

                if self.debug:
                    print(f"  [CEE] operation=tool_call:{function_name} principal=agent:react-agent")

                # Execute the tool
                if function_name in self.tool_functions:
                    result = self.tool_functions[function_name](**arguments)
                else:
                    result = f"Unknown tool: {function_name}"

                if self.debug:
                    print(f"    state_delta={result[:100]}...")

                # Add tool result to messages
                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": str(result),
                })

        return "Max turns reached without completion."
