/**
 * SPDX 2.3 JSON from the SBOM `generateSbom` builds. Only library components are written: SPDX 2.3 has no type for
 * models, datasets or services, so the AI inventory stays CycloneDX-only. Licenses that are not SPDX ids or expressions
 * (free text from a lockfile) are NOASSERTION here, because SPDX would need the license text to carry them.
 */
import type { Bom, LibraryComponent } from "./cyclonedx.js";

export interface SpdxDocument {
  spdxVersion: "SPDX-2.3";
  dataLicense: "CC0-1.0";
  SPDXID: "SPDXRef-DOCUMENT";
  name: string;
  documentNamespace: string;
  creationInfo: { created: string; creators: string[] };
  packages: SpdxPackage[];
  relationships: Array<{ spdxElementId: string; relatedSpdxElement: string; relationshipType: "DESCRIBES" | "DEPENDS_ON" }>;
}
export interface SpdxPackage {
  SPDXID: string;
  name: string;
  versionInfo?: string;
  downloadLocation: "NOASSERTION";
  filesAnalyzed: false;
  checksums?: Array<{ algorithm: "SHA1" | "SHA256" | "SHA384" | "SHA512"; checksumValue: string }>;
  externalRefs?: Array<{ referenceCategory: "PACKAGE-MANAGER"; referenceType: "purl"; referenceLocator: string }>;
  licenseConcluded: "NOASSERTION";
  licenseDeclared: string;
  copyrightText: "NOASSERTION";
}

const ALGORITHMS = { "SHA-1": "SHA1", "SHA-256": "SHA256", "SHA-384": "SHA384", "SHA-512": "SHA512" } as const;
const isLibrary = (component: Bom["components"][number]): component is LibraryComponent => component.type === "library";

function declaredLicense(component: LibraryComponent): string {
  const only = component.licenses?.length === 1 ? component.licenses[0]! : undefined;
  if (!only) return "NOASSERTION";
  if ("expression" in only) return only.expression;
  return "id" in only.license ? only.license.id : "NOASSERTION";
}

export function toSpdx(bom: Bom): SpdxDocument {
  const libraries = bom.components.filter(isLibrary);
  const ids = new Map(libraries.map((component, index) => [component["bom-ref"], `SPDXRef-Package-${index + 1}`]));
  const root = "SPDXRef-RootPackage";
  const name = bom.metadata.component.name;
  const packages: SpdxPackage[] = [
    { SPDXID: root, name, downloadLocation: "NOASSERTION", filesAnalyzed: false, licenseConcluded: "NOASSERTION", licenseDeclared: "NOASSERTION", copyrightText: "NOASSERTION" },
    ...libraries.map((component): SpdxPackage => ({
      SPDXID: ids.get(component["bom-ref"])!, name: component.name, versionInfo: component.version, downloadLocation: "NOASSERTION", filesAnalyzed: false,
      ...(component.hashes?.length ? { checksums: component.hashes.map(hash => ({ algorithm: ALGORITHMS[hash.alg], checksumValue: hash.content })) } : {}),
      externalRefs: [{ referenceCategory: "PACKAGE-MANAGER", referenceType: "purl", referenceLocator: component.purl }],
      licenseConcluded: "NOASSERTION", licenseDeclared: declaredLicense(component), copyrightText: "NOASSERTION",
    })),
  ];
  const relationships: SpdxDocument["relationships"] = [{ spdxElementId: "SPDXRef-DOCUMENT", relatedSpdxElement: root, relationshipType: "DESCRIBES" }];
  const dependedOn = new Set<string>();
  for (const dependency of bom.dependencies ?? []) {
    const from = ids.get(dependency.ref);
    for (const ref of dependency.dependsOn) {
      const to = ids.get(ref);
      if (from && to) { relationships.push({ spdxElementId: from, relatedSpdxElement: to, relationshipType: "DEPENDS_ON" }); dependedOn.add(ref); }
    }
  }
  // The application depends on the components nothing else depends on: where the lockfile records no graph, that is all of them.
  for (const component of libraries) if (!dependedOn.has(component["bom-ref"])) relationships.push({ spdxElementId: root, relatedSpdxElement: ids.get(component["bom-ref"])!, relationshipType: "DEPENDS_ON" });
  const uuid = bom.serialNumber.replace(/^urn:uuid:/, "");
  return {
    spdxVersion: "SPDX-2.3", dataLicense: "CC0-1.0", SPDXID: "SPDXRef-DOCUMENT", name,
    documentNamespace: `https://spdx.org/spdxdocs/${encodeURIComponent(name)}-${uuid}`,
    creationInfo: { created: bom.metadata.timestamp.replace(/\.\d+Z$/, "Z"), creators: bom.metadata.tools.components.map(tool => `Tool: ${tool.name}-${tool.version}`) },
    packages, relationships,
  };
}
