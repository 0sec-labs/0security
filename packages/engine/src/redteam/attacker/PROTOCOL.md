# Chat agent protocol (commandChatDriver)

The agent under test is a child process. The driver speaks JSON lines (one JSON object per line, UTF-8, newline terminated).

- stdin, driver to agent: `{"type":"user","text":"<message>"}` once per turn. The driver sends the next message only after it has the reply.
- stdout, agent to driver: `{"type":"reply","text":"<answer>"}` once per turn. Lines that are not JSON or have another type are ignored, so the agent may log to stdout.
- stderr is drained and discarded, so a full pipe cannot block the agent. A stdin error (EPIPE) or more than maxLineBytes (default 1 MiB) of stdout without a newline fails the turn.
- Tool calls are not part of the protocol. The agent's tools are the honeypot MCP server, which appends one JSON line per call to the trace file whose path is given in the driver options (the format parseTrace in ../judge.ts reads: seq, tool, privilege, args). The agent must have finished writing the calls for a turn before it prints that turn's reply.
- After each reply the driver reads the trace bytes appended since the last turn and returns the new events as that turn's calls. A missing file counts as empty. Only complete lines count.
- The trace is untrusted unless the agent is isolated from the file. Without isolation (a container or user that cannot write the file) the agent can forge calls, truncate or fill it, so a hit is not proof. The driver defends as far as it can: each event must have a numeric integer seq, a tool name of 1 to 128 characters, a privilege that is one of source, read-local, write-local, network-out, exec or unknown (missing means unknown), and object args; other lines are skipped. A shrinking file, a seq that does not increase, more than maxTraceBytes (4 MiB) or maxTraceEvents (1000) in one turn is a driver error (`driver-error`) and ends the driver.
- Timeouts: if no reply arrives within turnTimeoutMs (default 30000) send rejects, and runAttack stops with `driver-error`. If the process exits before replying, send rejects the same way.
- close() ends stdin, sends SIGTERM to the process group, escalates to SIGKILL after killGraceMs (default 2000) and waits until the process and its group are gone. For the group kill, spawn the agent detached (spawnAgentProcess does); otherwise only the child is signalled. The caller of runAttack owns the driver and closes it.
