/**
 * Framework Signatures
 *
 * Canonical lists of module paths, decorator names, class names, and method names
 * for every supported agentic framework. Used by both Python and TypeScript semantic
 * indexes to identify tool/action registration points and dangerous operations.
 *
 * Adding a new framework:
 *   1. Add a TS entry to KNOWN_FRAMEWORKS_TS (or KNOWN_FRAMEWORKS_PYTHON for Python).
 *   2. Wire the new entry in the semantic index (extractSemanticInvocationRoots).
 */

// ---------------------------------------------------------------------------
// TypeScript / JavaScript frameworks
// ---------------------------------------------------------------------------

/**
 * A single TypeScript/JavaScript framework descriptor.
 */
export interface TSFrameworkSignature {
  /** Human-readable framework name (used in CEE `framework` field) */
  name: string;
  /** NPM package imports that signal this framework is in use */
  moduleTokens: string[];
  /**
   * Object-literal property names whose presence (combined with an agentic
   * import) strongly suggests this is a tool/action registration.
   */
  handlerProps: string[];
  /**
   * Function/method call names used to register tools with this framework.
   * e.g. server.tool(), agent.addTool(), mcpServer.tool()
   */
  registrationCallees: string[];
  /**
   * Decorator names (without @) that mark a function as an agent tool.
   */
  decorators: string[];
}

/**
 * Known TypeScript/JavaScript agentic frameworks and their signatures.
 */
export const KNOWN_FRAMEWORKS_TS: TSFrameworkSignature[] = [
  // -------------------------------------------------------------------------
  // ElizaOS / eliza
  // -------------------------------------------------------------------------
  {
    name: 'elizaos',
    moduleTokens: ['@elizaos/core', '@elizaos/plugin', 'elizaos', 'eliza-core', '@ai16z/eliza'],
    handlerProps: ['handler', 'execute', 'run', 'action', 'perform'],
    registrationCallees: [
      'registerAction',
      'registerPlugin',
      'registerEvaluator',
      'registerProvider',
    ],
    decorators: [],
  },

  // -------------------------------------------------------------------------
  // Model Context Protocol (MCP) SDK
  // -------------------------------------------------------------------------
  {
    name: 'mcp',
    moduleTokens: [
      '@modelcontextprotocol/sdk',
      'modelcontextprotocol',
      '@mcp/',
      'mcp-framework',
    ],
    handlerProps: ['handler', 'execute'],
    registrationCallees: ['server.tool', 'mcpServer.tool', 'addTool', 'setRequestHandler'],
    decorators: ['tool', 'Tool'],
  },

  // -------------------------------------------------------------------------
  // OpenAI Agents SDK (openai-agents)
  // -------------------------------------------------------------------------
  {
    name: 'openai-agents',
    moduleTokens: ['openai-agents', 'openai/agents', '@openai/agents'],
    handlerProps: ['execute', 'handler', 'run'],
    registrationCallees: ['Agent', 'tool', 'function_tool'],
    decorators: ['tool'],
  },

  // -------------------------------------------------------------------------
  // Vercel AI SDK
  // -------------------------------------------------------------------------
  {
    name: 'vercel-ai',
    moduleTokens: ['ai', '@ai-sdk/', 'vercel-ai'],
    handlerProps: ['execute', 'handler'],
    registrationCallees: ['tool', 'createTool'],
    decorators: [],
  },

  // -------------------------------------------------------------------------
  // LangChain.js / LangGraph.js
  // -------------------------------------------------------------------------
  {
    name: 'langchain',
    moduleTokens: [
      'langchain',
      '@langchain/',
      'langgraph',
      '@langchain/core',
      '@langchain/community',
      '@langchain/langgraph',
    ],
    handlerProps: ['func', 'execute', 'handler', 'call'],
    registrationCallees: [
      'DynamicTool',
      'DynamicStructuredTool',
      'StructuredTool',
      'Tool',
      'tool',
      'createTool',
      'AgentExecutor',
    ],
    decorators: ['tool'],
  },

  // -------------------------------------------------------------------------
  // Mastra
  // -------------------------------------------------------------------------
  {
    name: 'mastra',
    moduleTokens: ['@mastra/core', 'mastra', '@mastra/'],
    handlerProps: ['execute', 'handler', 'run'],
    registrationCallees: ['createTool', 'tool', 'Agent', 'Workflow'],
    decorators: [],
  },

  // -------------------------------------------------------------------------
  // Anthropic / Claude
  // -------------------------------------------------------------------------
  {
    name: 'anthropic',
    moduleTokens: ['@anthropic-ai/sdk', 'anthropic'],
    handlerProps: ['execute', 'handler'],
    registrationCallees: ['messages.create'],
    decorators: [],
  },

  // -------------------------------------------------------------------------
  // CrewAI (JS port / wrappers)
  // -------------------------------------------------------------------------
  {
    name: 'crewai-js',
    moduleTokens: ['crewai', '@crewai/', 'crew-ai'],
    handlerProps: ['execute', 'run', 'handler'],
    registrationCallees: ['Tool', 'tool', 'Agent', 'Crew'],
    decorators: ['tool'],
  },

  // -------------------------------------------------------------------------
  // AutoGen (JS port)
  // -------------------------------------------------------------------------
  {
    name: 'autogen-js',
    moduleTokens: ['autogen', '@microsoft/autogen'],
    handlerProps: ['execute', 'handler', 'run'],
    registrationCallees: ['tool', 'AssistantAgent', 'UserProxyAgent'],
    decorators: ['tool'],
  },

  // -------------------------------------------------------------------------
  // Playwright / Puppeteer (browser automation - common in agent tool sets)
  // -------------------------------------------------------------------------
  {
    name: 'browser-automation',
    moduleTokens: ['playwright', 'puppeteer', 'selenium-webdriver'],
    handlerProps: ['execute', 'run', 'handler'],
    registrationCallees: [],
    decorators: [],
  },

  // -------------------------------------------------------------------------
  // Inngest (workflow / step functions used by agents)
  // -------------------------------------------------------------------------
  {
    name: 'inngest',
    moduleTokens: ['inngest'],
    handlerProps: ['handler', 'run'],
    registrationCallees: ['createFunction', 'inngest.createFunction'],
    decorators: [],
  },

  // -------------------------------------------------------------------------
  // Temporal.io (durable workflows)
  // -------------------------------------------------------------------------
  {
    name: 'temporal',
    moduleTokens: ['@temporalio/'],
    handlerProps: ['execute', 'run'],
    registrationCallees: ['defineActivity', 'defineWorkflow'],
    decorators: ['activity', 'workflow'],
  },
];

// ---------------------------------------------------------------------------
// Python frameworks
// ---------------------------------------------------------------------------

/**
 * A single Python framework descriptor.
 */
export interface PythonFrameworkSignature {
  /** Human-readable framework name (used in CEE `framework` field) */
  name: string;
  /** Python import paths (top-level packages or dotted sub-modules) */
  importTokens: string[];
  /**
   * Decorator names (without @) that mark a function as an agent tool.
   * Both simple names ('tool') and fully qualified paths ('langchain.tools.tool').
   */
  decoratorNames: string[];
  /**
   * Function/class call names used to build a tool object.
   * e.g. Tool(...), StructuredTool.from_function(...)
   */
  toolConstructors: string[];
  /**
   * Method names used to register tools with an agent/runner object.
   * e.g. agent.register_for_execution(name), pipeline.add_component(name, obj)
   */
  registrationMethods: string[];
}

/**
 * Known Python agentic frameworks and their signatures.
 */
export const KNOWN_FRAMEWORKS_PYTHON: PythonFrameworkSignature[] = [
  // -------------------------------------------------------------------------
  // LangChain / LangGraph
  // -------------------------------------------------------------------------
  {
    name: 'langchain',
    importTokens: ['langchain', 'langchain_core', 'langgraph', 'langchain_community'],
    decoratorNames: ['tool', 'langchain.tools.tool', 'langchain_core.tools.tool'],
    toolConstructors: [
      'Tool',
      'StructuredTool',
      'StructuredTool.from_function',
      'DynamicTool',
      'BaseTool',
    ],
    registrationMethods: ['bind_tools', 'with_structured_output', 'create_react_agent'],
  },

  // -------------------------------------------------------------------------
  // CrewAI
  // -------------------------------------------------------------------------
  {
    name: 'crewai',
    importTokens: ['crewai', 'crewai_tools'],
    decoratorNames: ['tool', 'crewai.tools.tool'],
    toolConstructors: ['Tool', 'BaseTool', 'Agent', 'Crew'],
    registrationMethods: ['tools'],
  },

  // -------------------------------------------------------------------------
  // AutoGen (v0.2 and v0.4)
  // -------------------------------------------------------------------------
  {
    name: 'autogen',
    importTokens: ['autogen', 'pyautogen', 'autogen_agentchat', 'autogen_core', 'autogen_ext'],
    decoratorNames: ['tool', 'autogen.tools.tool'],
    toolConstructors: [
      'AssistantAgent',
      'UserProxyAgent',
      'ConversableAgent',
      'FunctionTool',
    ],
    registrationMethods: ['register_for_execution', 'register_for_llm', 'register_reply'],
  },

  // -------------------------------------------------------------------------
  // OpenAI (function calling / Swarm)
  // -------------------------------------------------------------------------
  {
    name: 'openai',
    importTokens: ['openai', 'openai.types'],
    decoratorNames: [],
    toolConstructors: ['Agent', 'Swarm'],
    registrationMethods: ['functions'],
  },

  // -------------------------------------------------------------------------
  // Pydantic AI
  // -------------------------------------------------------------------------
  {
    name: 'pydantic-ai',
    importTokens: ['pydantic_ai', 'pydantic-ai'],
    decoratorNames: ['tool', 'agent.tool', 'agent.tool_plain', 'pydantic_ai.tool'],
    toolConstructors: ['Agent', 'Tool'],
    registrationMethods: ['tool', 'tool_plain'],
  },

  // -------------------------------------------------------------------------
  // LlamaIndex
  // -------------------------------------------------------------------------
  {
    name: 'llamaindex',
    importTokens: ['llama_index', 'llama-index', 'llama_index.core', 'llama_index.tools'],
    decoratorNames: ['tool'],
    toolConstructors: ['FunctionTool', 'QueryEngineTool', 'BaseTool', 'ToolMetadata'],
    registrationMethods: ['from_defaults', 'from_function'],
  },

  // -------------------------------------------------------------------------
  // Haystack
  // -------------------------------------------------------------------------
  {
    name: 'haystack',
    importTokens: ['haystack', 'haystack_experimental'],
    decoratorNames: ['component', 'tool'],
    toolConstructors: ['Pipeline', 'Agent'],
    registrationMethods: ['add_component', 'connect'],
  },

  // -------------------------------------------------------------------------
  // Google ADK / Generative AI
  // -------------------------------------------------------------------------
  {
    name: 'google-adk',
    importTokens: ['google.adk', 'google.generativeai', 'google_generativeai', 'vertexai'],
    decoratorNames: ['tool'],
    toolConstructors: ['Agent', 'LlmAgent', 'SequentialAgent', 'ParallelAgent'],
    registrationMethods: ['tools'],
  },

  // -------------------------------------------------------------------------
  // Smolagents (HuggingFace)
  // -------------------------------------------------------------------------
  {
    name: 'smolagents',
    importTokens: ['smolagents', 'transformers.agents'],
    decoratorNames: ['tool'],
    toolConstructors: ['Tool', 'CodeAgent', 'ReactCodeAgent', 'ToolCallingAgent'],
    registrationMethods: ['tools'],
  },

  // -------------------------------------------------------------------------
  // Model Context Protocol (Python SDK)
  // -------------------------------------------------------------------------
  {
    name: 'mcp',
    importTokens: ['mcp', 'mcp.server', 'mcp.types'],
    decoratorNames: ['tool', 'server.tool'],
    toolConstructors: ['Server', 'FastMCP'],
    registrationMethods: ['list_tools', 'call_tool'],
  },

  // -------------------------------------------------------------------------
  // Semantic Kernel (Python)
  // -------------------------------------------------------------------------
  {
    name: 'semantic-kernel',
    importTokens: ['semantic_kernel', 'semantic-kernel'],
    decoratorNames: ['kernel_function', 'sk_function'],
    toolConstructors: ['KernelFunction', 'KernelPlugin'],
    registrationMethods: ['add_plugin', 'add_function'],
  },

  // -------------------------------------------------------------------------
  // BeeAI / bee-agent-framework
  // -------------------------------------------------------------------------
  {
    name: 'beeai',
    importTokens: ['beeai', 'bee_agent_framework'],
    decoratorNames: ['tool'],
    toolConstructors: ['Tool', 'Agent', 'ReActAgent'],
    registrationMethods: ['tools'],
  },

  // -------------------------------------------------------------------------
  // Agno (previously phidata)
  // -------------------------------------------------------------------------
  {
    name: 'agno',
    importTokens: ['agno', 'phi', 'phidata'],
    decoratorNames: ['tool'],
    toolConstructors: ['Agent', 'Tool', 'Toolkit'],
    registrationMethods: ['tools'],
  },
];

// ---------------------------------------------------------------------------
// Shared constants
// ---------------------------------------------------------------------------

/**
 * All module tokens from all TypeScript frameworks flattened into a single set.
 * Used for fast "is this an agentic file?" checks without iterating the full list.
 */
export const ALL_TS_MODULE_TOKENS: ReadonlySet<string> = new Set(
  KNOWN_FRAMEWORKS_TS.flatMap((f) => f.moduleTokens),
);

/**
 * All import tokens from all Python frameworks flattened into a single set.
 */
export const ALL_PYTHON_IMPORT_TOKENS: ReadonlySet<string> = new Set(
  KNOWN_FRAMEWORKS_PYTHON.flatMap((f) => f.importTokens),
);
