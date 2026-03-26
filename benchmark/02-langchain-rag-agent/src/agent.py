"""LangChain RAG agent with document manipulation."""

import os
from pathlib import Path
from dotenv import load_dotenv

from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from langchain_community.vectorstores import FAISS
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import RunnablePassthrough
from langchain_core.output_parsers import StrOutputParser
from langchain.agents import create_tool_calling_agent, AgentExecutor

from .tools.document_rewriter import read_document, execute_transform, rewrite_document, add_document
from .tools.web_search import search_web, fetch_url

load_dotenv()


class RAGAgent:
    """RAG-augmented agent with document manipulation capabilities."""

    def __init__(self):
        self.llm = ChatOpenAI(model="gpt-4o", temperature=0)
        self.embeddings = OpenAIEmbeddings()
        self.documents_dir = Path(os.getenv("DOCUMENTS_DIR", "./documents"))
        self.vector_store_path = Path(os.getenv("VECTOR_STORE_PATH", "./vector_store"))

        self.tools = [
            read_document,
            execute_transform,
            rewrite_document,
            add_document,
            search_web,
            fetch_url,
        ]

        self._load_or_create_vector_store()
        self._setup_agent()

    def _load_or_create_vector_store(self):
        """Load existing vector store or create from documents."""
        if self.vector_store_path.exists():
            self.vector_store = FAISS.load_local(
                str(self.vector_store_path),
                self.embeddings,
                allow_dangerous_deserialization=True,
            )
        else:
            documents = self._load_documents()
            if documents:
                self.vector_store = FAISS.from_texts(documents, self.embeddings)
                self.vector_store.save_local(str(self.vector_store_path))
            else:
                self.vector_store = None

    def _load_documents(self) -> list[str]:
        """Load all documents from the documents directory."""
        documents = []
        self.documents_dir.mkdir(parents=True, exist_ok=True)

        # AFB04 INFO: Directory enumeration
        for doc_path in self.documents_dir.glob("*.txt"):
            # AFB04 INFO: Bulk file read
            content = doc_path.read_text()
            documents.append(f"[{doc_path.stem}]\n{content}")

        return documents

    def _setup_agent(self):
        """Set up the LangChain agent with tools."""
        prompt = ChatPromptTemplate.from_messages([
            ("system", """You are a helpful RAG assistant with access to a document store.
You can search documents, fetch web content, and modify documents when needed.
Always cite your sources and be helpful."""),
            ("human", "{input}"),
            ("placeholder", "{agent_scratchpad}"),
        ])

        agent = create_tool_calling_agent(self.llm, self.tools, prompt)
        self.executor = AgentExecutor(agent=agent, tools=self.tools, verbose=True)

    def query(self, question: str) -> str:
        """Query the RAG agent."""
        context = ""
        if self.vector_store:
            docs = self.vector_store.similarity_search(question, k=3)
            context = "\n\n".join(doc.page_content for doc in docs)

        enhanced_input = f"Context from document store:\n{context}\n\nQuestion: {question}"
        result = self.executor.invoke({"input": enhanced_input})
        return result["output"]
