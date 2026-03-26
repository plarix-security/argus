"""LangGraph supervisor/worker multi-agent system."""

import os
from typing import Annotated, Literal, TypedDict
from dotenv import load_dotenv

from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages

from .agents.coder_agent import execute_code, execute_python, read_code, save_code
from .agents.researcher_agent import web_research, summarize_findings
from .tools.shared_state import get_shared_state, update_shared_state

load_dotenv()


class AgentState(TypedDict):
    messages: Annotated[list, add_messages]
    current_agent: str
    task_complete: bool


class SupervisorSystem:
    """Multi-agent supervisor system."""

    def __init__(self):
        self.llm = ChatOpenAI(model="gpt-4o", temperature=0)
        self.max_iterations = int(os.getenv("MAX_ITERATIONS", "10"))

        self.researcher_tools = [web_research, summarize_findings, get_shared_state, update_shared_state]
        self.coder_tools = [execute_code, execute_python, read_code, save_code, get_shared_state, update_shared_state]
        self.critic_tools = [get_shared_state, update_shared_state]

        self.graph = self._build_graph()

    def _build_graph(self) -> StateGraph:
        """Build the LangGraph supervisor graph."""
        graph = StateGraph(AgentState)

        graph.add_node("supervisor", self._supervisor_node)
        graph.add_node("researcher", self._researcher_node)
        graph.add_node("coder", self._coder_node)
        graph.add_node("critic", self._critic_node)

        graph.add_edge(START, "supervisor")

        graph.add_conditional_edges(
            "supervisor",
            self._route_to_worker,
            {"researcher": "researcher", "coder": "coder", "critic": "critic", "end": END},
        )

        graph.add_edge("researcher", "supervisor")
        graph.add_edge("coder", "supervisor")
        graph.add_edge("critic", "supervisor")

        return graph.compile()

    def _supervisor_node(self, state: AgentState) -> AgentState:
        """Supervisor decides which worker to route to."""
        messages = state["messages"]

        response = self.llm.invoke([
            {"role": "system", "content": """You are a supervisor routing tasks to workers:
- researcher: for web research and information gathering
- coder: for writing and executing code
- critic: for reviewing output quality
- end: when task is complete

Respond with just the worker name or 'end'."""},
            *messages,
        ])

        return {"messages": [response], "current_agent": "supervisor", "task_complete": False}

    def _route_to_worker(self, state: AgentState) -> Literal["researcher", "coder", "critic", "end"]:
        """Route based on supervisor decision."""
        last_message = state["messages"][-1].content.lower().strip()

        if "researcher" in last_message:
            return "researcher"
        elif "coder" in last_message:
            return "coder"
        elif "critic" in last_message:
            return "critic"
        return "end"

    def _researcher_node(self, state: AgentState) -> AgentState:
        """Researcher agent for web research."""
        llm_with_tools = self.llm.bind_tools(self.researcher_tools)
        response = llm_with_tools.invoke(state["messages"])
        return {"messages": [response], "current_agent": "researcher", "task_complete": False}

    def _coder_node(self, state: AgentState) -> AgentState:
        """Coder agent for code execution."""
        llm_with_tools = self.llm.bind_tools(self.coder_tools)
        response = llm_with_tools.invoke(state["messages"])
        return {"messages": [response], "current_agent": "coder", "task_complete": False}

    def _critic_node(self, state: AgentState) -> AgentState:
        """Critic agent for review."""
        llm_with_tools = self.llm.bind_tools(self.critic_tools)
        response = llm_with_tools.invoke(state["messages"])
        return {"messages": [response], "current_agent": "critic", "task_complete": False}

    def run(self, task: str) -> str:
        """Execute the multi-agent workflow."""
        initial_state = {
            "messages": [{"role": "user", "content": task}],
            "current_agent": "supervisor",
            "task_complete": False,
        }

        final_state = self.graph.invoke(initial_state)
        return final_state["messages"][-1].content
