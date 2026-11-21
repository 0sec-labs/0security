import type { ModelFileResult } from "./scan.js";

const RULE_ID = "0/model-unsafe-deserialization";

/** SARIF 2.1.0 for code scanning: one result per file with dangerous imports, located at the file. */
export function modelScanToSarif(files: ModelFileResult[], options: { toolVersion: string; uri?: (file: ModelFileResult) => string }): object {
  const uri = options.uri ?? (file => file.path);
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: {
        driver: {
          name: "0 sbom scan-models",
          version: options.toolVersion,
          informationUri: "https://github.com/0sec-labs/0security",
          rules: [{
            id: RULE_ID,
            name: "UnsafeModelDeserialization",
            shortDescription: { text: "Model file imports callables that can run code when it is loaded" },
            fullDescription: { text: "Pickle-based model files run the callables they reference when they are loaded. This file references imports that run commands, load code or use the network." },
            defaultConfiguration: { level: "error" },
            help: { text: "Do not load this file. Re-export the weights as safetensors, or load with a restricted unpickler (for example torch.load(..., weights_only=True)) after confirming where the file came from." },
          }],
        },
      },
      results: files.filter(file => file.verdict === "dangerous").map(file => ({
        ruleId: RULE_ID,
        level: "error",
        message: { text: `${file.summary}.` },
        locations: [{ physicalLocation: { artifactLocation: { uri: uri(file).split("\\").join("/") } } }],
        properties: { format: file.format, imports: file.findings.filter(item => item.risk === "dangerous").map(item => item.qualified), complete: file.complete },
      })),
    }],
  };
}
