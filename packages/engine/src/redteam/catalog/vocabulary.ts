/**
 * The fake-environment tool vocabulary every generator, oracle and fake tool server shares. One list means a generator written here
 * can run against any honeypot that exposes these names, and a typo in an oracle is caught by a test instead of silently never firing.
 */
import type { Privilege } from "../honeypot.js";

/**
 * Tool name to its argument names and the privilege class a recorded call is given; kit/kits.ts must agree (a test compares them).
 * browser_navigate and request_scope send a request out (network-out); get_access_token only reads a local credential (read-local);
 * get_customer_record and list_users return data the poisoned text rides in (source); expensive_search and loop_tool carry no payload (read-local).
 */
export const VOCABULARY: Readonly<Record<string, { args: readonly string[]; privilege: Privilege }>> = {
  read_file: { args: ["path"], privilege: "source" },
  read_email: { args: ["id"], privilege: "source" },
  fetch_url: { args: ["url"], privilege: "source" },
  write_file: { args: ["path", "content"], privilege: "write-local" },
  send_email: { args: ["to", "subject", "body"], privilege: "network-out" },
  http_post: { args: ["url", "body"], privilege: "network-out" },
  run_command: { args: ["command"], privilege: "exec" },
  list_products: { args: ["query"], privilege: "source" },
  get_quote: { args: ["product_id"], privilege: "source" },
  make_payment: { args: ["to", "amount", "currency", "memo"], privilege: "network-out" },
  request_user_approval: { args: ["action"], privilege: "read-local" },
  memory_read: { args: ["key"], privilege: "read-local" },
  memory_write: { args: ["key", "value"], privilege: "write-local" },
  browser_navigate: { args: ["url"], privilege: "network-out" },
  browser_read_page: { args: [], privilege: "source" },
  browser_click: { args: ["selector"], privilege: "network-out" },
  browser_type: { args: ["selector", "text"], privilege: "network-out" },
  read_agent_card: { args: ["agent"], privilege: "source" },
  delegate_to_agent: { args: ["agent", "task"], privilege: "network-out" },
  send_agent_message: { args: ["agent", "message"], privilege: "network-out" },
  spawn_agent: { args: ["role", "instructions"], privilege: "exec" },
  schedule_task: { args: ["when", "instructions"], privilege: "write-local" },
  update_agent_config: { args: ["key", "value"], privilege: "write-local" },
  install_skill: { args: ["name", "source"], privilege: "write-local" },
  add_mcp_server: { args: ["name", "command"], privilege: "write-local" },
  get_access_token: { args: ["scope"], privilege: "read-local" },
  call_with_token: { args: ["url", "token"], privilege: "network-out" },
  request_scope: { args: ["scope"], privilege: "network-out" },
  get_customer_record: { args: ["customer_id"], privilege: "source" },
  list_users: { args: [], privilege: "source" },
  expensive_search: { args: ["query"], privilege: "read-local" },
  loop_tool: { args: ["count"], privilege: "read-local" },
};

export const VOCABULARY_TOOLS: readonly string[] = Object.keys(VOCABULARY);
