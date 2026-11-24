---
title: Browsers and 0security
description: "Bring your own browser MCP server to 0security as an extension, and know what protects you when you do."
---

0 has no built-in browser. You can add a browser MCP server as an extension so a Thread can open pages. Add one only for apps you own.

## Add a browser server

Run this command. It shows the install prompt with the exact command, and installs nothing until you approve it with `--yes`:

```bash
0security skills extensions mcp pw -- npx -y @playwright/mcp@0.0.86 --headless --isolated
```

Pin the version, as shown. The server is saved turned off. Enable it, and it starts when a Thread first uses it. See [MCP servers](/extensions/#mcp-servers).

This recipe has not been run end to end. The command shape comes from the CLI help and the [Extensions](/extensions/) page.

## What protects you

Approvals still apply. Starting the server goes through your "Ask before running commands" setting, and you approve the exact command first.

## What does not protect you

The server runs without a sandbox, with your network access. The operating system sandbox cannot confine a browser. Network is all or nothing, and the macOS profile cannot run Chromium. See [Sandboxing](/extensions/#sandboxing).

A page can contain prompt injection. Text on a page can try to steer the Thread. Tool results are untrusted.

## Keep it to your own apps

Point the browser at apps you own, on loopback, such as `http://127.0.0.1:3000`. Do not browse the open web or sign in to real accounts with it.
