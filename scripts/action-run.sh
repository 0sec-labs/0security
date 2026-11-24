#!/usr/bin/env bash
# The steps of the 0 GitHub Action (action.yml). Usage: action-run.sh scan | sbom | result
#
# Every input arrives as an environment variable that action.yml sets from `inputs.*`. No input is ever
# interpolated into script text. Each value is checked here, then passed to 0 as one argv element.
# Text that reaches the job summary or an annotation is reduced to a safe character set first.
set -uo pipefail

fail() { echo "::error::$1"; exit 2; }
warn() { echo "::warning::$1"; }

# --- validation -----------------------------------------------------------------------------------------

# check <input-name> <value> <extended-regex>: the whole value must match; a leading dash never does.
check() {
  local name=$1 value=$2 re=$3
  if [[ $value == -* ]] || ! [[ $value =~ $re ]]; then fail "Input $name has an unsupported value."; fi
}

# oneof <input-name> <value> <word>...: the value is one of the words.
oneof() {
  local name=$1 value=$2 w
  shift 2
  for w in "$@"; do [ "$value" = "$w" ] && return 0; done
  fail "Input $name must be one of: $*."
}

# realdir <dir> -> the physical path of an existing directory.
realdir() { (cd "$1" 2>/dev/null && pwd -P); }

# realpath_of <path> -> the physical path of an existing file or folder, links resolved.
realpath_of() {
  if [ -d "$1" ]; then realdir "$1"
  elif [ -f "$1" ]; then
    local d
    d=$(realdir "$(dirname "$1")") || return 1
    printf '%s/%s\n' "$d" "$(basename "$1")"
  else return 1; fi
}

WS_REAL=""
TMP_REAL=""
init_roots() {
  [ -n "${GITHUB_WORKSPACE:-}" ] && WS_REAL=$(realdir "$GITHUB_WORKSPACE")
  [ -n "${RUNNER_TEMP:-}" ] && TMP_REAL=$(realdir "$RUNNER_TEMP")
  [ -n "$WS_REAL" ] || fail "GITHUB_WORKSPACE is not set."
  [ -n "$TMP_REAL" ] || fail "RUNNER_TEMP is not set."
}

# inside <path> <root>
inside() { [ "$1" = "$2" ] || [[ $1 == "$2"/* ]]; }

# resolve_path <input-name> <value>: sets REPLY to the real path. The path must exist and, after links are
# resolved, stay inside the workspace or the runner temp folder. Relative paths are relative to the workspace.
resolve_path() {
  local name=$1 value=$2 abs
  check "$name" "$value" '^[A-Za-z0-9._/+@=-]+$'
  case $value in /*) abs=$value ;; *) abs="$WS_REAL/$value" ;; esac
  REPLY=$(realpath_of "$abs") || fail "Input $name names a path that does not exist."
  if ! inside "$REPLY" "$WS_REAL" && ! inside "$REPLY" "$TMP_REAL"; then
    fail "Input $name must stay inside the workspace."
  fi
}

# resolve_list <input-name> <comma-list> <array-name>: each item is resolved; the array holds the real paths.
resolve_list() {
  local name=$1 value=$2 out=$3 item
  check "$name" "$value" '^[A-Za-z0-9._/+@=,-]+$'
  [[ $value == ,* || $value == *, || $value == *,,* || $value == *,-* ]] && fail "Input $name has an unsupported value."
  local -a items=()
  IFS=, read -ra items <<< "$value"
  eval "$out=()"
  for item in "${items[@]}"; do
    resolve_path "$name" "$item"
    eval "$out+=(\"\$REPLY\")"
  done
}

# The operator's files (rules, tiers, context, policy, known results) steer the scan. A file that lives in the
# scanned repository, when the checkout is the pull request's own code, is controlled by whoever wrote the pull request.
SCAN_TOP=""
PR_CODE=""
workspace_is_pr_code() {
  [ -n "$PR_CODE" ] && { [ "$PR_CODE" = yes ]; return; }
  PR_CODE=no
  local head parent
  head=${HEAD_SHA:-}
  if [[ $head =~ ^[0-9a-f]{40}$ ]]; then
    [ "$(git -C "$WS_REAL" rev-parse HEAD 2>/dev/null)" = "$head" ] && PR_CODE=yes
    parent=$(git -C "$WS_REAL" rev-parse 'HEAD^2' 2>/dev/null) && [ "$parent" = "$head" ] && PR_CODE=yes
  fi
  [ "$PR_CODE" = yes ]
}

trust_check() {
  local name=$1 real=$2 dir top
  dir=$real
  [ -d "$real" ] || dir=$(dirname "$real")
  top=$(git -C "$dir" rev-parse --show-toplevel 2>/dev/null) || return 0
  top=$(realdir "$top") || return 0
  [ "$top" = "$SCAN_TOP" ] || return 0
  case "${GITHUB_EVENT_NAME:-}" in pull_request|pull_request_target) ;; *) return 0 ;; esac
  workspace_is_pr_code || return 0
  local fork=no
  [ -n "${HEAD_REPO:-}" ] && [ "$HEAD_REPO" != "${GITHUB_REPOSITORY:-}" ] && fork=yes
  if [ "$fork" = yes ] || [ "${GITHUB_EVENT_NAME:-}" = pull_request_target ]; then
    fail "Input $name points into the pull request's own code, so its author controls it. Use a file from the base branch or a separate checkout."
  fi
  warn "Input $name points into the pull request's own code, so the change under review can edit it. Use a file from the base branch or a separate checkout."
}

# clean <text>: one line, a short safe character set, at most 300 characters. No @mentions, #refs or markup.
clean() {
  printf '%s' "$1" | LC_ALL=C tr -d '\000-\037' | LC_ALL=C sed 's/[^A-Za-z0-9 .,;:()\/_=+-]//g' | cut -c1-300
}

num() { [[ ${1:-} =~ ^[0-9]{1,9}$ ]] && printf '%s' "$1" || printf '0'; }

out() { [ -n "${GITHUB_OUTPUT:-}" ] && printf '%s=%s\n' "$1" "$2" >> "$GITHUB_OUTPUT"; return 0; }
summary() { [ -n "${GITHUB_STEP_SUMMARY:-}" ] && printf '%s\n' "$1" >> "$GITHUB_STEP_SUMMARY"; return 0; }

ZERO=${ZERO_BIN:-0security}

# --- scan -----------------------------------------------------------------------------------------------

validate_scan() {
  resolve_path target "${TARGET:-.}"; TARGET_REAL=$REPLY
  SCAN_TOP=$(git -C "$TARGET_REAL" rev-parse --show-toplevel 2>/dev/null) && SCAN_TOP=$(realdir "$SCAN_TOP") || SCAN_TOP=""
  check budget "${BUDGET:-5}" '^[0-9]+(\.[0-9]+)?$'
  check passes "${PASSES:-1}" '^[1-5]$'
  [ -z "${MODEL:-}" ] || check model "$MODEL" '^[A-Za-z0-9._:/@+-]+$'
  [ -z "${FAIL_ON:-}" ] || oneof fail-on "$FAIL_ON" critical high medium low info
  [ -z "${SKILL:-}" ] || check skill "$SKILL" '^[A-Za-z0-9._:/@+-]+$'
  oneof upload "${UPLOAD:-true}" true false
  oneof allow-partial "${ALLOW_PARTIAL:-false}" true false
  oneof only-new "${ONLY_NEW:-false}" true false
  [ -z "${DIFF_BASE:-}" ] || check diff-base "$DIFF_BASE" '^[A-Za-z0-9._/@+~^-]+$'

  SCANNERS=()
  if [ -n "${SCANNER:-}" ]; then
    check scanner "$SCANNER" '^[a-z0-9,-]+$'
    local s
    IFS=, read -ra SCANNERS <<< "$SCANNER"
    [[ $SCANNER == ,* || $SCANNER == *, || $SCANNER == *,,* ]] && fail "Input scanner has an unsupported value."
    for s in "${SCANNERS[@]}"; do
      oneof scanner "$s" foxguard semgrep opengrep gitleaks trivy osv-scanner checkov
    done
  fi

  RULES_LIST=(); KNOWN_LIST=(); CONTEXT_LIST=(); POLICY_LIST=(); TIERS_REAL=""; SCOPE_REAL=""
  if [ -n "${RULES:-}" ]; then
    local ok=no s
    for s in ${SCANNERS[@]+"${SCANNERS[@]}"}; do [ "$s" = semgrep ] || [ "$s" = opengrep ] && ok=yes; done
    [ "$ok" = yes ] || fail "Input rules needs scanner to include semgrep or opengrep."
    resolve_list rules "$RULES" RULES_LIST
  fi
  [ -z "${KNOWN_SARIF:-}" ] || resolve_list known-sarif "$KNOWN_SARIF" KNOWN_LIST
  [ -z "${CONTEXT:-}" ] || resolve_list context "$CONTEXT" CONTEXT_LIST
  [ -z "${POLICY:-}" ] || resolve_list policy "$POLICY" POLICY_LIST
  if [ -n "${TIERS:-}" ]; then resolve_path tiers "$TIERS"; TIERS_REAL=$REPLY; fi
  if [ -n "${SCOPE:-}" ]; then resolve_path scope "$SCOPE"; SCOPE_REAL=$REPLY; fi
  if [ "$ONLY_NEW_SET" = yes ] && [ ${#KNOWN_LIST[@]} -eq 0 ]; then fail "Input only-new needs known-sarif."; fi

  local f
  for f in ${RULES_LIST[@]+"${RULES_LIST[@]}"}; do trust_check rules "$f"; done
  for f in ${KNOWN_LIST[@]+"${KNOWN_LIST[@]}"}; do trust_check known-sarif "$f"; done
  for f in ${CONTEXT_LIST[@]+"${CONTEXT_LIST[@]}"}; do trust_check context "$f"; done
  for f in ${POLICY_LIST[@]+"${POLICY_LIST[@]}"}; do trust_check policy "$f"; done
  [ -z "$TIERS_REAL" ] || trust_check tiers "$TIERS_REAL"
  # The declared scope can label real findings out of scope and take them out of fail-on, so a file the pull request
  # itself controls must not supply it. Use the base branch's SECURITY.md (git show origin/main:SECURITY.md).
  [ -z "$SCOPE_REAL" ] || trust_check scope "$SCOPE_REAL"
}

# summarise_sarif <sarif> <code> <mode-label>: sets STATUS and COVERAGE, writes the job summary.
read_report() {
  local sarif=$1 code=$2 meta
  STATUS=failed; COVERAGE=""; FAILURE=""; FILES=""
  M_OUT=0; M_TOTAL=0; M_CRIT=0; M_HIGH=0; M_MED=0; M_LOW=0; M_INFO=0
  TIER=""; KNOWN_NEW=""; KNOWN_OLD=""; KNOWN_HIDDEN=""
  if [ "$code" = 2 ] || [ ! -s "$sarif" ]; then return; fi
  case $code in 0|1) STATUS=complete ;; 3) STATUS=partial ;; esac
  command -v jq >/dev/null 2>&1 || { COVERAGE="Not read: jq is not installed on this runner."; return; }
  meta=$(jq -c '
    (.runs[0] // {}) as $r
    | [($r.results // [])[] | select((.properties.severity // null) != null)] as $all
    | [$all[] | select((.properties.scope // "") != "out-of-scope")] as $f
    | [$all[] | select((.properties.scope // "") == "out-of-scope")] as $o
    | { status: ($r.properties.status // ""),
        coverage: ($r.properties.coverage.statement // ""),
        failure: ($r.properties.failure.message // ""),
        files: (($r.properties.coverage // $r.properties.fileCoverage // {}) as $c | if ($c.opened // null) != null and ($c.inScope // null) != null then "\($c.opened) of \($c.inScope) source files opened, \($c.rounds.used // 0) follow-up round\(if ($c.rounds.used // 0) == 1 then "" else "s" end)" else "" end),
        total: ($f | length),
        outOfScope: ($o | length),
        critical: ([$f[] | select(.properties.severity == "critical")] | length),
        high: ([$f[] | select(.properties.severity == "high")] | length),
        medium: ([$f[] | select(.properties.severity == "medium")] | length),
        low: ([$f[] | select(.properties.severity == "low")] | length),
        info: ([$f[] | select(.properties.severity == "info")] | length),
        tier: (if $r.properties.tier then ($r.properties.tier.name // "") + " (" + ($r.properties.tier.source // "") + ")" else "" end),
        knownNew: (if $r.properties.known then $r.properties.known.findings.new else null end),
        knownOld: (if $r.properties.known then $r.properties.known.findings.alreadyKnown else null end),
        knownHidden: (if $r.properties.known then ($r.properties.known.hidden // 0) else null end) }' "$sarif" 2>/dev/null) || return
  local s
  s=$(jq -r '.status' <<< "$meta")
  case $s in
    complete|partial|skipped|prepass_only|failed) STATUS=$s ;;
    budget_exhausted|timed_out) STATUS=partial ;;
  esac
  COVERAGE=$(clean "$(jq -r '.coverage' <<< "$meta")")
  FAILURE=$(clean "$(jq -r '.failure' <<< "$meta")")
  FILES=$(clean "$(jq -r '.files' <<< "$meta")")
  M_TOTAL=$(num "$(jq -r '.total' <<< "$meta")"); M_CRIT=$(num "$(jq -r '.critical' <<< "$meta")")
  M_HIGH=$(num "$(jq -r '.high' <<< "$meta")"); M_MED=$(num "$(jq -r '.medium' <<< "$meta")")
  M_LOW=$(num "$(jq -r '.low' <<< "$meta")"); M_INFO=$(num "$(jq -r '.info' <<< "$meta")")
  M_OUT=$(num "$(jq -r '.outOfScope' <<< "$meta")")
  TIER=$(clean "$(jq -r '.tier' <<< "$meta")")
  KNOWN_NEW=$(jq -r '.knownNew // empty' <<< "$meta"); KNOWN_OLD=$(jq -r '.knownOld // empty' <<< "$meta")
  KNOWN_HIDDEN=$(jq -r '.knownHidden // empty' <<< "$meta")
  [ -z "$KNOWN_NEW" ] || KNOWN_NEW=$(num "$KNOWN_NEW")
  [ -z "$KNOWN_OLD" ] || KNOWN_OLD=$(num "$KNOWN_OLD")
  [ -z "$KNOWN_HIDDEN" ] || KNOWN_HIDDEN=$(num "$KNOWN_HIDDEN")
  if [ -z "$COVERAGE" ]; then
    case $STATUS in
      partial) COVERAGE="The review stopped early (budget or time limit); the findings are partial." ;;
      skipped) COVERAGE="Nothing was scanned: the tier skipped this repository." ;;
      prepass_only) COVERAGE="Only the pattern scanners ran; no model reviewed the code." ;;
      complete) COVERAGE="The scan finished the review it planned." ;;
    esac
  fi
}

write_summary() {
  summary "## 0 security scan"
  summary ""
  summary "- Status: $STATUS"
  summary "- Coverage: ${COVERAGE:-not reported}"
  [ -z "$FILES" ] || summary "- Files opened: $FILES"
  [ -z "$FAILURE" ] || summary "- Why it stopped: $FAILURE"
  summary "- Exit code: $1"
  if [ "$STATUS" != failed ]; then
    summary "- Findings: $M_TOTAL (critical $M_CRIT, high $M_HIGH, medium $M_MED, low $M_LOW, info $M_INFO)"
    [ "$M_OUT" = 0 ] || summary "- Outside declared scope: $M_OUT (listed in the report, not counted above and not part of fail-on)"
    [ -z "$TIER" ] || summary "- Tier: $TIER"
    if [ -n "$KNOWN_NEW" ]; then
      summary "- Second opinion: $KNOWN_NEW new, $KNOWN_OLD already known${KNOWN_HIDDEN:+, $KNOWN_HIDDEN left out}"
    fi
  fi
  summary ""
}

cmd_scan() {
  init_roots
  ONLY_NEW_SET=no; [ "${ONLY_NEW:-false}" = true ] && ONLY_NEW_SET=yes
  validate_scan
  local sarif="$TMP_REAL/0.sarif" base="${DIFF_BASE:-}" s f args
  rm -f "$sarif"
  args=(scan "$TARGET_REAL" --format sarif -o "$sarif" --budget "$BUDGET" --passes "$PASSES")
  if [ -z "$base" ] && [ -n "${GITHUB_BASE_REF:-}" ]; then
    check base-ref "$GITHUB_BASE_REF" '^[A-Za-z0-9._/@+-]+$'
    # A checkout with fetch-depth 0 already has the base branch; then no credentials are needed.
    git -C "$WS_REAL" rev-parse --verify --quiet "refs/remotes/origin/${GITHUB_BASE_REF}" >/dev/null ||
      git -C "$WS_REAL" fetch --no-tags --depth=1 origin "+refs/heads/${GITHUB_BASE_REF}:refs/remotes/origin/${GITHUB_BASE_REF}" || fail "Could not fetch the base branch."
    base="origin/${GITHUB_BASE_REF}"
  fi
  [ -z "$base" ] || args+=(--diff "$base")
  [ -z "${MODEL:-}" ] || args+=(--model "$MODEL")
  [ -z "${FAIL_ON:-}" ] || args+=(--fail-on "$FAIL_ON")
  [ -z "${SKILL:-}" ] || args+=(--skill "$SKILL")
  for s in ${SCANNERS[@]+"${SCANNERS[@]}"}; do args+=(--scanner "$s"); done
  for f in ${RULES_LIST[@]+"${RULES_LIST[@]}"}; do args+=(--rules "$f"); done
  for f in ${KNOWN_LIST[@]+"${KNOWN_LIST[@]}"}; do args+=(--known "$f"); done
  [ "$ONLY_NEW_SET" = no ] || args+=(--only-new)
  for f in ${CONTEXT_LIST[@]+"${CONTEXT_LIST[@]}"}; do args+=(--context "$f"); done
  for f in ${POLICY_LIST[@]+"${POLICY_LIST[@]}"}; do args+=(--policy "$f"); done
  [ -z "$TIERS_REAL" ] || args+=(--tiers "$TIERS_REAL")
  [ -z "$SCOPE_REAL" ] || args+=(--scope "$SCOPE_REAL")
  [ "${ALLOW_PARTIAL:-false}" != true ] || args+=(--allow-partial)

  "$ZERO" "${args[@]}"
  local code=$?
  read_report "$sarif" "$code"
  out sarif "$sarif"; out code "$code"; out status "$STATUS"; out coverage "$COVERAGE"
  write_summary "$code"
  # Upload first, then the result step decides whether the job fails.
  exit 0
}

# --- sbom -----------------------------------------------------------------------------------------------

cmd_sbom() {
  init_roots
  resolve_path target "${TARGET:-.}"; local target=$REPLY
  oneof upload "${UPLOAD:-true}" true false
  [ -z "${LICENSES_PRESET:-}" ] || oneof licenses-preset "$LICENSES_PRESET" permissive no-copyleft
  [ -z "${FAIL_ON:-}" ] || oneof fail-on "$FAIL_ON" critical high medium low info
  local sbom="$TMP_REAL/sbom.cdx.json" sarif="$TMP_REAL/0-sbom.sarif" gen chk=0 lic=0
  rm -f "$sbom" "$sarif"
  "$ZERO" sbom generate "$target" -o "$sbom"; gen=$?
  if [ "$gen" -eq 0 ] && [ -s "$sbom" ]; then
    "$ZERO" sbom check "$sbom" --format sarif -o "$sarif"; chk=$?
    if [ -n "${LICENSES_PRESET:-}" ]; then "$ZERO" sbom licenses "$sbom" --preset "$LICENSES_PRESET"; lic=$?; fi
  fi
  local code=0 comps="" advisories=0
  if [ "$gen" -ne 0 ] || [ "$chk" -gt 1 ] || [ "$lic" -gt 1 ]; then code=2
  elif [ "$chk" -eq 1 ] || [ "$lic" -eq 1 ]; then code=1; fi
  [ "$code" = 2 ] && STATUS=failed || STATUS=complete
  if [ "$code" != 2 ] && command -v jq >/dev/null 2>&1; then
    comps=$(num "$(jq -r '.components | length' "$sbom" 2>/dev/null)")
    advisories=$(num "$(jq -r '[.runs[0].results[]?] | length' "$sarif" 2>/dev/null)")
  fi
  COVERAGE="SBOM from lockfiles; advisories come from the public OSV database."
  out sarif "$sarif"; out sbom "$sbom"; out code "$code"; out status "$STATUS"; out coverage "$COVERAGE"
  out advisories-code "$chk"; out licenses-code "$lic"
  summary "## 0 SBOM check"
  summary ""
  summary "- Status: $STATUS"
  [ "$code" = 2 ] || summary "- Components: ${comps:-0}"
  [ "$code" = 2 ] || summary "- Advisories: $advisories"
  [ "$code" = 2 ] || [ -z "${LICENSES_PRESET:-}" ] || summary "- License policy ($LICENSES_PRESET): $([ "$lic" -eq 0 ] && echo pass || echo violation)"
  summary ""
  exit 0
}

# --- result ---------------------------------------------------------------------------------------------

cmd_result() {
  local code=${CODE:-2} status=${STATUS:-failed}
  case "${MODE:-scan}" in
    sbom)
      [ "$code" = 2 ] && { echo "::error::The SBOM step could not finish. See the log above."; exit 1; }
      if [ "${LICENSES_CODE:-0}" = 1 ]; then echo "::error::A component has a license the policy does not allow."; exit 1; fi
      if [ "${ADVISORIES_CODE:-0}" = 1 ]; then
        if [ -n "${FAIL_ON:-}" ]; then echo "::error::The SBOM has components with known advisories (fail-on is set)."; exit 1; fi
        warn "The SBOM has components with known advisories. Set fail-on to fail the job on them."
      fi
      exit 0 ;;
  esac
  case "$status" in
    skipped) echo "::notice::The scan was skipped by the tier map. Nothing was reviewed." ;;
    prepass_only) warn "Only the pattern scanners ran. No model reviewed the code." ;;
    partial) warn "The scan did not review everything, so the findings are partial. Raise budget, or continue with: 0 scan <folder> --resume latest" ;;
  esac
  case "$code" in
    0) ;;
    1) echo "::error::The scan found a finding at or above fail-on, or it failed. See the log above."; exit 1 ;;
    3) echo "::error::The scan stopped before it reviewed everything (partial). Set allow-partial to true to accept a partial scan, or raise budget."; exit 1 ;;
    *) echo "::error::The scan exited with code $code."; exit 1 ;;
  esac
}

case "${1:-}" in
  scan) cmd_scan ;;
  sbom) cmd_sbom ;;
  result) cmd_result ;;
  *) echo "usage: action-run.sh scan|sbom|result" >&2; exit 2 ;;
esac
