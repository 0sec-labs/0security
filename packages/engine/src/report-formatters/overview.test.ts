import { describe, expect, it } from "vitest";
import type { Finding, ScanReport } from "../shared/index.js";
import { renderOverview } from "./overview.js";

describe("report overview", () => {
  it("preserves ungrouped findings and links every finding once", () => {
    const findings = ["a", "b", "c"].map(id => ({ id, title: id, description: "Context", severity: "high", evidence: { request: "", response: "" } }) as Finding);
    const report = { overview: { summary: "<script>unsafe</script>", groups: [{ title: "Isolation", summary: "A theme", nextStep: "Validate", findingIds: ["a", "a", "missing"] }, { title: "Execution", summary: "Another theme", nextStep: "Verify", findingIds: ["a", "b"] }] } } as unknown as ScanReport;
    const html = renderOverview(report, findings);
    expect(html.match(/data-open-finding=/g)).toHaveLength(3);
    expect(html).toContain("Other findings");
    expect(html).toContain('href="#finding-3"');
    expect(html).toContain("&lt;script&gt;unsafe&lt;/script&gt;");
    expect(html).not.toContain("<script>unsafe");
  });

  it("strips unsafe URL schemes (javascript:, data:) from observation links while keeping https links", () => {
    const findings = [{ id: "a", title: "a", description: "Context", severity: "high", evidence: { request: "", response: "" } } as Finding];
    const report = {
      overview: {
        summary: "Summary",
        groups: [],
        observations: [
          { title: "XSS payload", status: "observed", note: "Untrusted URL", url: "  JaVaScRiPt:alert(1)" },
          { title: "Data URL", status: "observed", note: "Untrusted data URL", url: "data:text/html,<script>alert(1)</script>" },
          { title: "Safe URL", status: "observed", note: "Valid interface", url: "https://app.example.com/admin" },
        ],
      },
    } as unknown as ScanReport;
    const html = renderOverview(report, findings);
    expect(html).not.toMatch(/href\s*=\s*"\s*javascript:/i);
    expect(html).not.toMatch(/href\s*=\s*"\s*data:/i);
    expect(html).toContain('href="https://app.example.com/admin"');
  });
});
