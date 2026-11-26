#!/usr/bin/env bash
# Enterprise evaluation flow with no model: scan a pinned public Java project with the in-repo Foxguard scanner,
# validate the SARIF, import it, triage findings, compare two commits, export reports and build the Bitbucket
# Code Insights payload to a file. It never calls a model and never contacts Bitbucket, AWS or an identity provider.
# The only network use is fetching the pinned checkout and the pinned SARIF schema.
#
# Recipe: docs/src/content/docs/enterprise-demo-flow.md
#
# Usage:
#   bash scripts/demo/enterprise-flow.sh [--keep] [--workdir DIR]
#
# Environment:
#   ZEROSEC_BIN      a CLI to run instead of building this checkout (the released 0.45.0 lacks `findings rollup --since` and `findings upload`)
#   FOXGUARD_BIN     a built scanner (default: build crates/foxguard with scripts/build-foxguard.sh)
#   PYTHON           python3 with the jsonschema package, for the SARIF schema check (default: python3)
#   DEMO_REPO_URL, DEMO_BASE_SHA, DEMO_HEAD_SHA   override the pinned project and the two commits
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
repo_url="${DEMO_REPO_URL:-https://github.com/WebGoat/WebGoat.git}"
base_sha="${DEMO_BASE_SHA:-bf79d42ee52920b4752d9caed0e496c85d947dbb}"
head_sha="${DEMO_HEAD_SHA:-4e98f1cbbf896fdd06edcc9930515ebe0ade7c69}"
schema_sha="1742a253eb654bf8a4ed7c60eaef7412b2c23553"
schema_url="https://raw.githubusercontent.com/oasis-tcs/sarif-spec/$schema_sha/sarif-2.1/schema/sarif-schema-2.1.0.json"
schema_hash="c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e"
python="${PYTHON:-python3}"

keep=0
work=""
while [ $# -gt 0 ]; do
  case "$1" in
    --keep) keep=1 ;;
    --workdir) shift; work="${1:?--workdir needs a folder}" ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

step_no=0
step() { step_no=$((step_no + 1)); printf '\n== Step %d: %s\n   proves: %s\n' "$step_no" "$1" "$2"; step_start=$SECONDS; }
done_step() { printf '   ok (%ds): %s\n' "$((SECONDS - step_start))" "$1"; }
die() { printf '\nFAILED at step %d: %s\n' "$step_no" "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is required but not on PATH"; }
json() { node -e "const d=JSON.parse(require('fs').readFileSync(process.argv[1],'utf8'));const v=($2);console.log(typeof v==='string'?v:JSON.stringify(v))" "$1"; }

if [ -z "$work" ]; then work="$(mktemp -d "${TMPDIR:-/tmp}/0-enterprise-demo.XXXXXX")"; else mkdir -p "$work"; [ -z "$(ls -A "$work")" ] || { echo "--workdir must be empty" >&2; exit 2; }; fi
work="$(cd "$work" && pwd)"
cleanup() { [ "$keep" -eq 1 ] || rm -rf "$work"; }
trap cleanup EXIT
echo "Work folder: $work$([ "$keep" -eq 1 ] && echo ' (kept)' || echo ' (removed on exit)')"

mkdir -p "$work/out"
db="$work/findings.db"
out="$work/out"
src="$work/src"
total_start=$SECONDS

need git; need node; need "$python"
"$python" -I -c "import jsonschema" 2>/dev/null || die "$python needs the jsonschema package (pip install jsonschema)"

# ---------------------------------------------------------------- 1
step "Build the in-repo CLI and scanner" "both come from this checkout: the CLI from packages/cli and the scanner Foxguard from crates/foxguard"
if [ -n "${ZEROSEC_BIN:-}" ]; then cli=("$ZEROSEC_BIN"); else
  need pnpm
  (cd "$root" && pnpm install --frozen-lockfile && pnpm --filter '@0/cli...' build) >"$out/build-cli.log" 2>&1 || { tail -20 "$out/build-cli.log" >&2; die "building the CLI failed"; }
  cli=(node "$root/packages/cli/dist/index.js")
fi
"${cli[@]}" findings --help 2>&1 | grep -q "rollup" || die "this CLI has no 'findings rollup'; use a build of this checkout"
if [ -n "${FOXGUARD_BIN:-}" ]; then fox="$FOXGUARD_BIN"; else
  INSTALL_DIR="$work/bin" bash "$root/scripts/build-foxguard.sh" >"$out/build-foxguard.log" 2>&1 || { tail -20 "$out/build-foxguard.log" >&2; die "scripts/build-foxguard.sh failed"; }
  fox="$work/bin/foxguard"
fi
[ -x "$fox" ] || die "scanner not found at $fox"
export ZERO_FOXGUARD_PATH="$fox"
done_step "$("${cli[@]}" --version) with $("$fox" --version 2>&1 | head -1)"

# From here on the run uses a throwaway HOME, so no earlier findings, config or credentials can leak into it.
# (The builds above run first, with the real HOME, because pnpm and cargo need their caches.)
export HOME="$work/home" XDG_CONFIG_HOME="$work/home/.config" XDG_DATA_HOME="$work/home/.local/share"
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null GIT_TERMINAL_PROMPT=0
unset OPENAI_API_KEY ANTHROPIC_API_KEY BITBUCKET_TOKEN AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
mkdir -p "$HOME"
# ---------------------------------------------------------------- 2
step "Fetch the two pinned commits" "the inputs are fixed by commit, so counts are repeatable"
git init -q "$src"
git -C "$src" remote add origin "$repo_url"
git -C "$src" fetch -q --depth 1 origin "$base_sha" || die "could not fetch $base_sha from $repo_url"
git -C "$src" fetch -q --depth 1 origin "$head_sha" || die "could not fetch $head_sha from $repo_url"
done_step "base $base_sha, head $head_sha"

tiers="$work/tiers.json"
printf '%s\n' '{"default":"standard","tiers":{"standard":{"prepassOnly":true}}}' > "$tiers"

scan_commit() { # label sha
  git -C "$src" checkout -q --detach "$2" || die "checkout of $2 failed"
  local started=$SECONDS
  "${cli[@]}" scan "$src" --tiers "$tiers" --format sarif -o "$out/$1.sarif" >"$out/$1.scan.log" 2>&1 || { tail -20 "$out/$1.scan.log" >&2; die "scan of $1 failed"; }
  eval "scan_seconds_$1=$((SECONDS - started))"
  [ -s "$out/$1.sarif" ] || die "scan of $1 wrote no SARIF"
}

# ---------------------------------------------------------------- 3
step "Scan the head commit, scanner only" "0security scan runs the pattern pre-pass with no model request (prepassOnly tier) and writes SARIF"
scan_commit head "$head_sha"
java_files="$(git -C "$src" ls-files '*.java' | wc -l | tr -d ' ')"
head_total="$(json "$out/head.sarif" "d.runs[0].results.length")"
grep -q "no model review" "$out/head.scan.log" || die "the scan log does not say that no model was used"
grep -q "not reviewed by a model" "$out/head.scan.log" || die "the scan log does not mark the findings as pre-pass only"
[ "$head_total" -gt 0 ] || die "the scan produced no findings on $java_files Java files; the scanner did not run"
done_step "$head_total findings in $java_files Java files, $scan_seconds_head seconds"

# ---------------------------------------------------------------- 4
step "Validate the SARIF against the OASIS 2.1.0 schema" "the file is valid SARIF, checked against a schema pinned by commit and SHA-256"
curl -fsSL "$schema_url" -o "$work/sarif-schema-2.1.0.json" || die "could not fetch the SARIF schema"
[ "$(shasum -a 256 "$work/sarif-schema-2.1.0.json" | cut -d' ' -f1)" = "$schema_hash" ] || die "the SARIF schema does not match the pinned SHA-256"
"$python" -I -c "
import json, sys, jsonschema
schema = json.load(open(sys.argv[1]))
doc = json.load(open(sys.argv[2]))
errors = list(jsonschema.Draft4Validator(schema).iter_errors(doc))
for e in errors[:5]: print('  schema error:', list(e.path), e.message[:200])
sys.exit(1 if errors else 0)
" "$work/sarif-schema-2.1.0.json" "$out/head.sarif" || die "head.sarif is not valid SARIF 2.1.0"
done_step "head.sarif has 0 schema errors"

# ---------------------------------------------------------------- 5
step "Import the SARIF into a findings database" "the findings reach the same store the console, exports and triage read"
"${cli[@]}" findings import "$out/head.sarif" --root "$src" --db-path "$db" --format json >"$out/import.json" || die "findings import failed"
imported="$(json "$out/import.json" "d.findings")"
[ "$imported" -eq "$head_total" ] || die "import reported $imported findings but the SARIF has $head_total"
"${cli[@]}" findings export --db-path "$db" --format json -o "$out/list.json" >/dev/null 2>&1 || die "findings export failed"
listed="$(json "$out/list.json" "(d.findings||d).length")"
[ "$listed" -gt 0 ] || die "the database holds no findings after import"
done_step "import reported '${imported:-n/a}', database holds $listed rows"

# ---------------------------------------------------------------- 6
step "Triage three findings with named reasons" "accept-risk needs a reason and an expiry, records the approver, and the finding reopens after the expiry"
ids=(); while IFS= read -r line; do ids+=("$line"); done < <(json "$out/list.json" "(d.findings||d).slice(0,3).map(f=>f.id).join('\n')")
[ "${#ids[@]}" -eq 3 ] || die "fewer than three findings to triage"
"${cli[@]}" findings accept "${ids[0]}" --db-path "$db" --reason "Lesson code that is vulnerable on purpose; never deployed" --expires 90d --approver "demo-security-lead" >/dev/null 2>&1 || die "accept failed"
"${cli[@]}" findings accept "${ids[1]}" --db-path "$db" --reason "Tracked in a risk register; fix planned next quarter" --expires 180d --approver "demo-security-lead" >/dev/null 2>&1 || die "accept failed"
"${cli[@]}" findings suppress "${ids[2]}" --db-path "$db" --note "Test fixture, not part of the shipped artifact" --approver "demo-security-lead" >/dev/null 2>&1 || die "suppress failed"
"${cli[@]}" findings export --db-path "$db" --triage accepted --format json -o "$out/accepted.json" >/dev/null 2>&1 || die "export accepted failed"
accepted="$(json "$out/accepted.json" "(d.findings||d).length")"
[ "$accepted" -eq 2 ] || die "expected 2 accepted findings, found $accepted"
"${cli[@]}" findings export --db-path "$db" --triage suppressed --format json -o "$out/suppressed.json" >/dev/null 2>&1 || die "export suppressed failed"
[ "$(json "$out/suppressed.json" "(d.findings||d).length")" -eq 1 ] || die "expected 1 suppressed finding"
"${cli[@]}" findings list --db-path "$db" --expiring 200 >"$out/expiring.txt" || die "list --expiring failed"
expiring="$(grep -c 'fp:' "$out/expiring.txt" || true)"
[ "$expiring" -eq 2 ] || die "expected both accepted findings to expire within 200 days, saw $expiring"
"${cli[@]}" findings show "${ids[0]}" --db-path "$db" >"$out/show.txt" || die "findings show failed"
grep -q "Lesson code that is vulnerable on purpose" "$out/show.txt" || die "the accept reason is not shown on the finding"
done_step "2 accepted with expiry, 1 suppressed; $expiring due within 200 days; reason visible on 'findings show'"

# ---------------------------------------------------------------- 7
step "New-only comparison between two commits" "a later commit reports what it opened and fixed against the earlier one, instead of the whole backlog"
scan_commit base "$base_sha"
base_total="$(json "$out/base.sarif" "d.runs[0].results.length")"
"${cli[@]}" findings rollup "$out/base.sarif" --repository webgoat --export "$out/base.rollup.json" --format json -o "$out/base.rollup-report.json" >/dev/null 2>&1 || die "rollup of the base scan failed"
"${cli[@]}" findings rollup "$out/head.sarif" --repository webgoat --since "$out/base.rollup.json" --format json -o "$out/diff.json" >/dev/null 2>&1 || die "rollup --since failed"
"${cli[@]}" findings rollup "$out/head.sarif" --repository webgoat --since "$out/base.rollup.json" --format text -o "$out/diff.txt" >/dev/null 2>&1 || die "text rollup --since failed"
grep '^Trend since' "$out/diff.txt" | sed 's/^/   /' || die "the comparison did not report opened and fixed counts"
opened="$(json "$out/diff.json" "d.trend.opened")"
fixed="$(json "$out/diff.json" "d.trend.fixed")"
# What the head opened and fixed against the base must account exactly for the change in the number of findings.
[ "$((base_total + opened - fixed))" -eq "$head_total" ] || die "base $base_total + opened $opened - fixed $fixed is not head $head_total (see $out/diff.json)"
[ "$opened" -lt "$head_total" ] || die "the comparison reported the whole backlog as new"
done_step "base $base_total + $opened opened - $fixed fixed = head $head_total; the review queue is $opened findings, not $head_total"

# ---------------------------------------------------------------- 8
step "Export the report formats" "the same findings leave as JSON, Markdown, SARIF and HTML, and the SARIF export is schema-valid"
for fmt in json md sarif html; do
  "${cli[@]}" findings export --db-path "$db" --format "$fmt" -o "$out/report.$fmt" >/dev/null 2>&1 || die "export as $fmt failed"
  [ -s "$out/report.$fmt" ] || die "export as $fmt is empty"
done
"$python" -I -c "
import json, sys, jsonschema
errors = list(jsonschema.Draft4Validator(json.load(open(sys.argv[1]))).iter_errors(json.load(open(sys.argv[2]))))
for e in errors[:5]: print('  schema error:', list(e.path), e.message[:200])
sys.exit(1 if errors else 0)
" "$work/sarif-schema-2.1.0.json" "$out/report.sarif" || die "exported SARIF is not valid"
done_step "json, md, sarif, html written ($(wc -c <"$out/report.json" | tr -d ' ') bytes of JSON)"

# ---------------------------------------------------------------- 9
step "Build the Bitbucket Code Insights payload to a file" "the Code Insights module turns findings into the report and annotation requests, with no token and no HTTP call"
"${cli[@]}" findings upload "$out/head.sarif" --to bitbucket-cloud --repo demo-workspace/demo-repo --commit "$head_sha" --print >"$out/code-insights.json" 2>"$out/code-insights.err" || die "payload build failed"
node -e "
const d=JSON.parse(require('fs').readFileSync(process.argv[1],'utf8'));
const batches=d.annotationBatches||[];
const sizes=batches.map(b=>b.length);
console.log('   platform='+d.platform+' total='+d.annotationsTotal+' emitted='+d.annotationsEmitted+' dropped='+d.annotationsDropped+' batches='+sizes.length+' max-batch='+Math.max(0,...sizes));
if(!d.report||!d.annotationsEmitted){console.error('empty payload');process.exit(1)}
if(Math.max(...sizes)>100){console.error('a batch exceeds the Bitbucket Cloud limit of 100');process.exit(1)}
if(d.annotationsEmitted>1000){console.error('more than 1000 annotations');process.exit(1)}
if(d.annotationsEmitted+d.annotationsDropped!==d.annotationsTotal){console.error('emitted + dropped != total');process.exit(1)}
" "$out/code-insights.json" || die "the Code Insights payload failed its checks"
done_step "payload at code-insights.json; Cloud limits respected (100 per request, 1000 per report)"

# ---------------------------------------------------------------- summary
sev="$(node -e "
const d=JSON.parse(require('fs').readFileSync(process.argv[1],'utf8'));
const c={};for(const r of d.runs[0].results){const l=r.level||'none';c[l]=(c[l]||0)+1}
console.log(Object.entries(c).map(([k,v])=>k+'='+v).join(' '))" "$out/head.sarif")"
printf '\n== Summary\n'
printf '   project: %s\n   base:    %s\n   head:    %s\n' "$repo_url" "$base_sha" "$head_sha"
printf '   Java files at head: %s\n   head scan: %s seconds, %s findings (%s)\n   base scan: %s seconds, %s findings\n' "$java_files" "$scan_seconds_head" "$head_total" "$sev" "$scan_seconds_base" "$base_total"
printf '   head vs base: %s opened, %s fixed\n' "$opened" "$fixed"
printf '   triage: 2 accepted (expiry set), 1 suppressed\n   total: %s seconds\n' "$((SECONDS - total_start))"
printf '\nAll %d steps passed. No model, Bitbucket, AWS or identity provider was contacted.\n' "$step_no"
[ "$keep" -eq 1 ] && printf 'Artifacts: %s\n' "$out" || true
