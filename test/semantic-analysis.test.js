const fs = require('fs');
const os = require('os');
const path = require('path');

const { AFBAnalyzer } = require('../dist/analyzer');

function makeTempProject(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wyscan-semantic-'));

  for (const [relativePath, content] of Object.entries(files)) {
    const fullPath = path.join(dir, relativePath);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });
    fs.writeFileSync(fullPath, content);
  }

  return dir;
}

describe('semantic-first python analysis', () => {
  test('manual OpenAI tool manifests resolve to semantic tool roots', async () => {
    const projectDir = makeTempProject({
      'agent.py': [
        'import os',
        'from openai import OpenAI',
        'from tools import calculate, CALCULATOR_TOOLS',
        '',
        'class ReactAgent:',
        '    def __init__(self):',
        '        self.client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))',
        '        self.tools = CALCULATOR_TOOLS',
        '        self.tool_functions = {"calculate": calculate}',
        '',
        '    def run(self, task: str):',
        '        return self.client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": task}], tools=self.tools)',
        '',
      ].join('\n'),
      'tools.py': [
        'def calculate(expression: str):',
        '    return eval(expression)',
        '',
        'CALCULATOR_TOOLS = [{"type": "function", "function": {"name": "calculate", "parameters": {"type": "object", "properties": {"expression": {"type": "string"}}}}}]',
        '',
      ].join('\n'),
    });

    const analyzer = new AFBAnalyzer();
    await analyzer.ensureInitialized();
    const report = analyzer.analyzeDirectory(projectDir);

    expect(report.totalCEEs).toBe(1);
    expect(report.cees[0].tool).toBe('calculate');
    expect(report.cees[0].framework).toBe('openai');
    expect(report.cees[0].evidenceKind).not.toBe('heuristic');
  });

  test('langgraph create_react_agent roots tools semantically', async () => {
    const projectDir = makeTempProject({
      'graph.py': [
        'from langgraph.prebuilt import create_react_agent',
        'from tools import cleanup_workspace',
        '',
        'def build_agent(model):',
        '    return create_react_agent(model, [cleanup_workspace])',
        '',
      ].join('\n'),
      'tools.py': [
        'import shutil',
        '',
        'def cleanup_workspace(target: str):',
        '    shutil.rmtree(target)',
        '',
      ].join('\n'),
    });

    const analyzer = new AFBAnalyzer();
    await analyzer.ensureInitialized();
    const report = analyzer.analyzeDirectory(projectDir);

    expect(report.totalCEEs).toBe(1);
    expect(report.cees[0].tool).toBe('cleanup_workspace');
    expect(report.cees[0].framework).toBe('langgraph');
    expect(report.cees[0].evidenceKind).not.toBe('heuristic');
  });

  test('autogen function_map roots tools semantically', async () => {
    const projectDir = makeTempProject({
      'executor.py': [
        'from autogen import UserProxyAgent',
        'import shutil',
        '',
        'def cleanup_workspace(target: str):',
        '    shutil.rmtree(target)',
        '',
        'FUNCTION_MAP = {"cleanup": cleanup_workspace}',
        'user_proxy = UserProxyAgent(name="executor", function_map=FUNCTION_MAP)',
        '',
      ].join('\n'),
    });

    const analyzer = new AFBAnalyzer();
    await analyzer.ensureInitialized();
    const report = analyzer.analyzeDirectory(projectDir);

    expect(report.totalCEEs).toBe(1);
    expect(report.cees[0].tool).toBe('cleanup_workspace');
    expect(report.cees[0].framework).toBe('autogen');
    expect(report.cees[0].evidenceKind).not.toBe('heuristic');
  });

  test('langchain create_tool_calling_agent roots tools semantically', async () => {
    const projectDir = makeTempProject({
      'agent.py': [
        'from langchain.agents import create_tool_calling_agent, AgentExecutor',
        'from langchain_openai import ChatOpenAI',
        'from langchain_core.prompts import ChatPromptTemplate',
        'from tools import execute_transform',
        '',
        'class RAGAgent:',
        '    def __init__(self):',
        '        self.llm = ChatOpenAI(model="gpt-4o")',
        '        self.tools = [execute_transform]',
        '        prompt = ChatPromptTemplate.from_messages([("human", "{input}")])',
        '        agent = create_tool_calling_agent(self.llm, self.tools, prompt)',
        '        self.executor = AgentExecutor(agent=agent, tools=self.tools)',
        '',
      ].join('\n'),
      'tools.py': [
        'from langchain_core.tools import tool',
        '',
        '@tool',
        'def execute_transform(code: str):',
        '    exec(code)',
        '',
      ].join('\n'),
    });

    const analyzer = new AFBAnalyzer();
    await analyzer.ensureInitialized();
    const report = analyzer.analyzeDirectory(projectDir);

    expect(report.totalCEEs).toBe(1);
    expect(report.cees[0].tool).toBe('execute_transform');
    expect(report.cees[0].framework).toBe('langchain');
    expect(report.cees[0].evidenceKind).not.toBe('heuristic');
  });

  test('extended tool bundles keep framework attachment for later-added tools', async () => {
    const projectDir = makeTempProject({
      'graph.py': [
        'from langgraph.prebuilt import create_react_agent',
        'from tools import BASE_TOOLS',
        '',
        'def build_agent(model):',
        '    return create_react_agent(model, BASE_TOOLS)',
        '',
      ].join('\n'),
      'tools.py': [
        'from langchain_core.tools import tool',
        'import shutil',
        '',
        '@tool',
        'def low_level(target: str):',
        '    shutil.rmtree(target)',
        '',
        '@tool',
        'def high_level(target: str):',
        '    return low_level.invoke({"target": target})',
        '',
        'BASE_TOOLS = [low_level]',
        'BASE_TOOLS.extend([high_level])',
        '',
      ].join('\n'),
    });

    const analyzer = new AFBAnalyzer();
    await analyzer.ensureInitialized();
    const report = analyzer.analyzeDirectory(projectDir);
    const highLevel = report.cees.filter((cee) => cee.tool === 'high_level');

    expect(highLevel).toHaveLength(1);
    expect(highLevel[0].framework).toBe('langgraph');
    expect(highLevel[0].callPath).toHaveLength(2);
  });

  test('semantic sink detection resolves imported requests and pathlib operations', async () => {
    const projectDir = makeTempProject({
      'tools.py': [
        'from pathlib import Path',
        'import requests',
        'from langchain.tools import tool',
        '',
        '@tool',
        'def export_report(target: str, url: str):',
        '    report_path = Path(target)',
        '    report_path.write_text("ok")',
        '    requests.post(url, data="ok")',
        '',
      ].join('\n'),
    });

    const analyzer = new AFBAnalyzer();
    await analyzer.ensureInitialized();
    const report = analyzer.analyzeDirectory(projectDir);

    expect(report.totalCEEs).toBe(2);
    expect(report.cees.every((cee) => cee.evidenceKind !== 'heuristic')).toBe(true);
    expect(report.cees.some((cee) => (cee.supportingEvidence || []).join(' ').includes('resolved receiver constructor pathlib.Path'))).toBe(true);
    expect(report.cees.some((cee) => (cee.supportingEvidence || []).join(' ').includes('resolved module alias requests'))).toBe(true);
  });

  test('path parent mkdir resolves semantically', async () => {
    const projectDir = makeTempProject({
      'tools.py': [
        'from pathlib import Path',
        'from langchain.tools import tool',
        '',
        '@tool',
        'def prepare_target(target: str):',
        '    full_path = Path(target)',
        '    full_path.parent.mkdir(parents=True, exist_ok=True)',
        '',
      ].join('\n'),
    });

    const analyzer = new AFBAnalyzer();
    await analyzer.ensureInitialized();
    const report = analyzer.analyzeDirectory(projectDir);

    expect(report.totalCEEs).toBe(1);
    expect(report.cees[0].evidenceKind).not.toBe('heuristic');
    expect(report.cees[0].supportingEvidence.join(' ')).toContain('resolved receiver constructor pathlib.Path');
  });

  test('with-open file handle writes resolve semantically', async () => {
    const projectDir = makeTempProject({
      'tools.py': [
        'from langchain.tools import tool',
        '',
        '@tool',
        'def append_note(target: str, message: str):',
        '    with open(target, "a", encoding="utf-8") as handle:',
        '        handle.write(message)',
        '',
      ].join('\n'),
    });

    const analyzer = new AFBAnalyzer();
    await analyzer.ensureInitialized();
    const report = analyzer.analyzeDirectory(projectDir);

    expect(report.totalCEEs).toBe(2);
    expect(report.cees.some((cee) => cee.operation.includes('builtins.open.write'))).toBe(true);
    expect(report.cees.every((cee) => cee.evidenceKind !== 'heuristic')).toBe(true);
  });

  test('helper-returned smtp clients keep semantic sink identity', async () => {
    const projectDir = makeTempProject({
      'tools.py': [
        'import smtplib',
        'from langchain.tools import tool',
        '',
        'def create_client():',
        '    return smtplib.SMTP("smtp.example.com", 25)',
        '',
        '@tool',
        'def send_notice(to_address: str, message: str):',
        '    client = create_client()',
        '    client.sendmail("from@example.com", [to_address], message)',
        '',
      ].join('\n'),
    });

    const analyzer = new AFBAnalyzer();
    await analyzer.ensureInitialized();
    const report = analyzer.analyzeDirectory(projectDir);

    expect(report.totalCEEs).toBe(2);
    expect(report.cees.some((cee) => cee.operation.includes('smtplib.SMTP.sendmail'))).toBe(true);
    expect(report.cees.every((cee) => cee.evidenceKind !== 'heuristic')).toBe(true);
  });

  test('database cursors and redis clients resolve semantically', async () => {
    const projectDir = makeTempProject({
      'tools.py': [
        'import sqlite3',
        'import redis',
        'from langchain.tools import tool',
        '',
        'redis_client = redis.Redis(host="localhost", port=6379, db=0)',
        '',
        'def get_db_connection():',
        '    return sqlite3.connect("test.db")',
        '',
        '@tool',
        'def run_query(sql: str, key: str):',
        '    conn = get_db_connection()',
        '    with conn.cursor() as cursor:',
        '        cursor.execute(sql)',
        '        cursor.fetchall()',
        '    redis_client.set(key, sql)',
        '    redis_client.get(key)',
        '',
      ].join('\n'),
    });

    const analyzer = new AFBAnalyzer();
    await analyzer.ensureInitialized();
    const report = analyzer.analyzeDirectory(projectDir);

    expect(report.totalCEEs).toBe(4);
    expect(report.cees.every((cee) => cee.evidenceKind !== 'heuristic')).toBe(true);
    expect(report.cees.some((cee) => cee.operation.includes('sqlite3.connect.cursor.execute'))).toBe(true);
    expect(report.cees.some((cee) => cee.operation.includes('redis.Redis.set'))).toBe(true);
  });

  test('semantic open classification respects write mode', async () => {
    const projectDir = makeTempProject({
      'tools.py': [
        'from langchain.tools import tool',
        '',
        '@tool',
        'def write_note(target: str):',
        '    with open(target, "w") as handle:',
        '        handle.write("hello")',
        '',
      ].join('\n'),
    });

    const analyzer = new AFBAnalyzer();
    await analyzer.ensureInitialized();
    const report = analyzer.analyzeDirectory(projectDir);

    expect(report.totalCEEs).toBe(2);
    const openCEE = report.cees.find((cee) => cee.codeSnippet.includes('open(target'));
    expect(openCEE).toBeDefined();
    expect(openCEE.severity).toBe('warning');
    expect(openCEE.evidenceKind).not.toBe('heuristic');
  });

  test('validation helper names do not downgrade structurally resolved paths', async () => {
    const projectDir = makeTempProject({
      'tools.py': [
        'import requests',
        'from langchain.tools import tool',
        '',
        'def validate_target(url: str):',
        '    requests.post(url, data="ok")',
        '',
        '@tool',
        'def export_data(url: str):',
        '    validate_target(url)',
        '',
      ].join('\n'),
    });

    const analyzer = new AFBAnalyzer();
    await analyzer.ensureInitialized();
    const report = analyzer.analyzeDirectory(projectDir);

    expect(report.totalCEEs).toBe(1);
    expect(report.cees[0].severity).toBe('warning');
    expect(report.findings[0].severity).toBe('warning');
  });

  test('sensitive names do not elevate structurally resolved paths', async () => {
    const projectDir = makeTempProject({
      'tools.py': [
        'import requests',
        'from langchain.tools import tool',
        '',
        '@tool',
        'def send_password(url: str, password: str):',
        '    requests.post(url, data=password)',
        '',
      ].join('\n'),
    });

    const analyzer = new AFBAnalyzer();
    await analyzer.ensureInitialized();
    const report = analyzer.analyzeDirectory(projectDir);

    expect(report.totalCEEs).toBe(1);
    expect(report.cees[0].severity).toBe('warning');
    expect(report.findings[0].severity).toBe('warning');
  });

  test('cee evidence records traced input flow into dangerous operations', async () => {
    const projectDir = makeTempProject({
      'tools.py': [
        'from langchain.tools import tool',
        'import shutil',
        '',
        '@tool',
        'def cleanup_agent(target: str):',
        '    path = target',
        '    shutil.rmtree(path)',
        '',
      ].join('\n'),
    });

    const analyzer = new AFBAnalyzer();
    await analyzer.ensureInitialized();
    const report = analyzer.analyzeDirectory(projectDir);

    expect(report.totalCEEs).toBe(1);
    expect(report.cees[0].evidenceKind).toBe('structural');
    expect(report.cees[0].supportingEvidence.join(' ')).toContain('Traced tool input into shutil.rmtree arguments');
    expect(report.cees[0].classificationNote).toContain('Traced tool-controlled input into the matched operation arguments.');
    expect(report.findings[0].confidence).toBeGreaterThan(0.85);
  });

  test('pattern fallback remains available when semantic roots are absent', async () => {
    const projectDir = makeTempProject({
      'tools.py': [
        'import shutil',
        '',
        'def action(fn):',
        '    return fn',
        '',
        '@action',
        'def cleanup_workspace(target: str):',
        '    shutil.rmtree(target)',
        '',
      ].join('\n'),
    });

    const analyzer = new AFBAnalyzer();
    await analyzer.ensureInitialized();
    const report = analyzer.analyzeDirectory(projectDir);

    expect(report.totalCEEs).toBe(1);
    expect(report.cees[0].framework).toBe('custom');
    expect(report.cees[0].evidenceKind).toBe('heuristic');
    expect(report.findings[0].confidence).toBeLessThan(0.8);
  });
});
