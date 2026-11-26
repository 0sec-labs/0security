import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const chart = join(dirname(fileURLToPath(import.meta.url)), "..", "deploy", "helm", "zero");
const hasHelm = spawnSync("helm", ["version", "--short"], { encoding: "utf8" }).status === 0;
const skip = hasHelm ? false : "helm is not installed";

function template(...args) {
  return spawnSync("helm", ["template", "r", chart, ...args], { encoding: "utf8" });
}

test("the chart lints", { skip }, () => {
  const lint = spawnSync("helm", ["lint", chart], { encoding: "utf8" });
  assert.equal(lint.status, 0, lint.stdout + lint.stderr);
});

test("the console is one replica with a retained volume and probes", { skip }, () => {
  const out = template();
  assert.equal(out.status, 0, out.stderr);
  assert.match(out.stdout, /kind: StatefulSet[\s\S]*replicas: 1\n/);
  assert.match(out.stdout, /whenDeleted: Retain/);
  assert.match(out.stdout, /readyz/);
  assert.match(out.stdout, /healthz/);
  assert.match(out.stdout, /kind: NetworkPolicy/);
  assert.match(out.stdout, /runAsNonRoot: true/);
  assert.match(out.stdout, /ZERO_ENTERPRISE/);
});

test("the replica count cannot be raised", { skip }, () => {
  const out = template("--set", "replicaCount=2");
  assert.notEqual(out.status, 0);
  assert.match(out.stderr, /replicaCount/);
});

test("an ingress needs a host, and the host becomes the allowed host and public URL", { skip }, () => {
  assert.notEqual(template("--set", "ingress.enabled=true", "--set", "ingress.tlsSecretName=x").status, 0);
  const plain = template("--set", "ingress.enabled=true", "--set", "ingress.host=0.example.test");
  assert.notEqual(plain.status, 0);
  assert.match(plain.stderr, /tlsSecretName/);
  const out = template("--set", "ingress.enabled=true", "--set", "ingress.host=0.example.test", "--set", "ingress.tlsSecretName=zero-tls");
  assert.equal(out.status, 0, out.stderr);
  assert.match(out.stdout, /secretName: zero-tls/);
  const upstream = template("--set", "ingress.enabled=true", "--set", "ingress.host=0.example.test", "--set", "ingress.tlsTerminatedUpstream=true");
  assert.equal(upstream.status, 0, upstream.stderr);
  assert.match(out.stdout, /localhost,127\.0\.0\.1,0\.example\.test/);
  assert.match(out.stdout, /https:\/\/0\.example\.test/);
  assert.match(out.stdout, /kind: Ingress/);
});

test("Entra ID, a team config and an existing secret reach the pod without a key in the chart", { skip }, () => {
  const out = template(
    "--set", "model.provider=azure", "--set", "model.azureEntra=true",
    "--set", "team.config.workspace.id=ws", "--set", "secrets.existingSecret=zero-secrets",
  );
  assert.equal(out.status, 0, out.stderr);
  assert.match(out.stdout, /AZURE_OPENAI_AUTH\n\s+value: entra/);
  assert.match(out.stdout, /ZERO_TEAM_CONFIG/);
  assert.match(out.stdout, /name: zero-secrets/);
  assert.doesNotMatch(out.stdout, /kind: Secret/);
});

const haValues = [
  "--set", "highAvailability.enabled=true",
  "--set", "highAvailability.databaseSecret.name=zero-db",
  "--set", "highAvailability.licenseSecret.name=zero-license",
  "--set", "secrets.existingSecret=zero-secrets",
  "--set", "highAvailability.databaseCIDRs={10.0.0.0/24}",
];

test("high availability runs replicas on a shared database, with a budget, a drain delay and no secret in the chart", { skip }, () => {
  const out = template(...haValues);
  assert.equal(out.status, 0, out.stderr);
  assert.match(out.stdout, /kind: StatefulSet[\s\S]*replicas: 2\n/);
  assert.match(out.stdout, /kind: PodDisruptionBudget[\s\S]*maxUnavailable: 1/);
  assert.match(out.stdout, /ZERO_HA_DATABASE_URL_FILE/);
  assert.match(out.stdout, /ZERO_LICENSE_FILE/);
  assert.match(out.stdout, /command: \["sleep", "10"\]/);
  assert.match(out.stdout, /port: 5432/);
  assert.match(out.stdout, /name: "zero-db"/);
  assert.doesNotMatch(out.stdout, /postgres(ql)?:\/\//);
  assert.doesNotMatch(out.stdout, /kind: Secret/);
});

test("without high availability the chart still renders one replica and no budget", { skip }, () => {
  const out = template();
  assert.match(out.stdout, /replicas: 1\n/);
  assert.doesNotMatch(out.stdout, /PodDisruptionBudget|ZERO_HA_DATABASE_URL_FILE|preStop/);
});

test("high availability refuses settings that would start replicas that cannot work together", { skip }, () => {
  const only = (drop) => haValues.filter((_, i, all) => !(all[i - 1] === "--set" && all[i].startsWith(drop)) && !(all[i] === "--set" && all[i + 1]?.startsWith(drop)));
  assert.match(template("--set", "highAvailability.enabled=true").stderr, /databaseSecret\.name/);
  assert.match(template(...only("highAvailability.licenseSecret")).stderr, /licenseSecret\.name/);
  assert.match(template(...only("secrets.existingSecret")).stderr, /shared sign-in/);
  assert.match(template(...only("highAvailability.databaseCIDRs")).stderr, /databaseCIDRs/);
  assert.match(template(...haValues, "--set", "terminationGracePeriodSeconds=35").stderr, /terminationGracePeriodSeconds/);
  assert.match(template(...haValues, "--set", "highAvailability.replicas=1").stderr, /replicas/);
});

test("replicaCount stays refused when high availability is on", { skip }, () => {
  assert.notEqual(template(...haValues, "--set", "replicaCount=3").status, 0);
});
