import { describe, expect, it } from "vitest";
import { checkThreatMap } from "../threat-map.js";

const wrap = (body: string) => `# T\n## Data flows\nx\n## Threat map\n${body}\n## Open questions\n- q\n`;
const ok = "```mermaid\nflowchart LR\n  subgraph Internet\n    user[\"Visitor\"]\n  end\n  subgraph App\n    api[\"API\"]:::unchecked\n  end\n  user -->|login| api\n```";

describe("checkThreatMap", () => {
  it("accepts a well-formed flowchart", () => expect(checkThreatMap(wrap(ok))).toEqual([]));
  it("accepts graph and an init directive", () => expect(checkThreatMap(wrap("```mermaid\n%%{init: {}}%%\ngraph TD\n a-->b\n```"))).toEqual([]));
  it("ignores undefined", () => expect(checkThreatMap(undefined)).toEqual([]));
  it("warns when the section is missing", () => expect(checkThreatMap("# T\n## Summary\nx")[0]).toMatch(/no diagram/));
  it("warns when there is no mermaid block", () => expect(checkThreatMap(wrap("prose only"))[0]).toMatch(/no ```mermaid block/));
  it("warns on an unclosed fence", () => expect(checkThreatMap(wrap("```mermaid\nflowchart LR\n a-->b"))).toEqual(expect.arrayContaining([expect.stringMatching(/never closed/)])));
  it("warns on wrong diagram type", () => expect(checkThreatMap(wrap("```mermaid\nsequenceDiagram\n a->>b: hi\n```"))[0]).toMatch(/should start with "flowchart"/));
  it("warns on unbalanced subgraphs", () => {
    expect(checkThreatMap(wrap("```mermaid\nflowchart LR\n subgraph A\n a-->b\n```"))).toEqual([expect.stringMatching(/1 "subgraph" without/)]);
    expect(checkThreatMap(wrap("```mermaid\nflowchart LR\n a-->b\n end\n```"))).toEqual([expect.stringMatching(/"end" without/)]);
  });
  it("warns when there are no arrows", () => expect(checkThreatMap(wrap("```mermaid\nflowchart LR\n a\n```"))).toEqual([expect.stringMatching(/no data flows/)]));
});
