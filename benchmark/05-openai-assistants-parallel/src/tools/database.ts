/**
 * Database tools for OpenAI Assistants customer support agent
 * Demonstrates SQL injection vulnerabilities
 */

import OpenAI from 'openai';
import Database from 'better-sqlite3';

const db = new Database('orders.db');
const client = new OpenAI();

// Tool definitions for OpenAI Assistants
const tools: OpenAI.ChatCompletionTool[] = [
  {
    type: 'function',
    function: {
      name: 'query_orders',
      description: 'Query customer orders by email or order ID',
      parameters: { type: 'object', properties: { query: { type: 'string' } } }
    }
  }
];

async function query_orders(query: string) {
  // VULNERABILITY: SQL injection - string interpolation
  const sql = `SELECT * FROM orders WHERE email = '${query}' OR order_id = '${query}'`;
  return db.exec(sql);
}

async function runAssistant(userMessage: string) {
  const response = await client.chat.completions.create({
    model: 'gpt-4',
    messages: [{ role: 'user', content: userMessage }],
    tools
  });
  return response;
}

async function process_refund(orderId: string, amount: number) {
  // VULNERABILITY: SQL injection in UPDATE
  const sql = `UPDATE orders SET refunded = 1, refund_amount = ${amount} WHERE order_id = '${orderId}'`;
  return db.exec(sql);
}

const refundTools: OpenAI.ChatCompletionTool[] = [
  {
    type: 'function',
    function: {
      name: 'process_refund',
      description: 'Process a refund for an order',
      parameters: { type: 'object', properties: { orderId: { type: 'string' }, amount: { type: 'number' } } }
    }
  }
];

async function get_customer(customerId: string) {
  // Database read - parameterized query
  const stmt = db.prepare('SELECT * FROM customers WHERE id = ?');
  return stmt.get(customerId);
}

export { query_orders, process_refund, get_customer, runAssistant };
