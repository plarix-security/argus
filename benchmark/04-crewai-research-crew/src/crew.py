"""CrewAI research crew configuration."""

import os
from dotenv import load_dotenv
from crewai import Agent, Crew, Task

from .tools.webhook import send_webhook, publish_to_default_webhook
from .tools.scraper import scrape_url, dynamic_scrape
from .tools.plan_file import read_plan, update_plan
from .tools.publish import publish_article

load_dotenv()


class ResearchCrew:
    """Four-agent research crew."""

    def __init__(self):
        self.planner = Agent(
            role="Research Planner",
            goal="Create structured research plans",
            backstory="Expert at breaking down research topics into actionable steps",
            tools=[read_plan, update_plan],
            verbose=True,
        )

        self.researcher = Agent(
            role="Web Researcher",
            goal="Gather comprehensive information from the web",
            backstory="Skilled at finding and extracting relevant information",
            tools=[scrape_url, dynamic_scrape, read_plan],
            verbose=True,
        )

        self.writer = Agent(
            role="Content Writer",
            goal="Write compelling, well-researched articles",
            backstory="Experienced technical writer with a clear, engaging style",
            tools=[read_plan, publish_article],
            verbose=True,
        )

        self.publisher = Agent(
            role="Content Publisher",
            goal="Publish content to external platforms",
            backstory="Expert at distributing content via webhooks and APIs",
            tools=[send_webhook, publish_to_default_webhook, read_plan],
            verbose=True,
        )

    def run(self, topic: str) -> str:
        """Execute the research crew workflow."""
        plan_task = Task(
            description=f"Create a research plan for: {topic}",
            expected_output="A structured research plan in markdown",
            agent=self.planner,
        )

        research_task = Task(
            description="Execute the research plan and gather information",
            expected_output="Comprehensive research notes",
            agent=self.researcher,
        )

        write_task = Task(
            description="Write a complete article based on the research",
            expected_output="A polished article in markdown format",
            agent=self.writer,
        )

        publish_task = Task(
            description="Publish the article to configured endpoints",
            expected_output="Confirmation of successful publication",
            agent=self.publisher,
        )

        crew = Crew(
            agents=[self.planner, self.researcher, self.writer, self.publisher],
            tasks=[plan_task, research_task, write_task, publish_task],
            verbose=True,
        )

        result = crew.kickoff()
        return str(result)
