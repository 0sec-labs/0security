---
title: Threat model and policy checks
description: Draft a reviewable threat model for a repository, steer scans with it, and check the code against policies written in Markdown.
---

A threat model and policies help a scan look past low-level bugs. Draft a threat model, write policies, and pass both to `0 scan`.

A threat model says what the system is, who the actors are and which authorization and business rules must hold, such as "only an admin may change a role". A policy is a rule your organisation wrote, such as "customer data must not go to a third-party processor". For each policy, 0 answers pass or fail with evidence.

Both are plain files that people review in a pull request. They use the same threads, skills and findings as `0 scan`.

## Draft a threat model

```bash
0 threat-model ./your-repo
0 threat-model ./your-repo --pr
```

A thread follows the `threat-model` skill, reads the code and writes one file, `.0/threat-model.md` (or the path in `--output`). It records no findings and changes no other file. When the folder's `SECURITY.md` has a `## Scope` section, the summary links to it. The section is read as data and does not change the draft.

The file has a fixed structure:

- Front matter with `title`, `generated` (date), `commit`, `generator` and `status: draft`.
- These sections, in order: Summary, What matters most, Assets, Actors, Trust boundaries, Entry points, Authorization and business rules, Data flows, Open questions.

The file names only what the thread saw, with `path:line`. Anything the code does not say is written as `unknown: confirm with the team` and listed under Open questions.

### Review and keep your edits

Mark text you wrote or approved with `<!-- human -->` on its own line before the text. Marked text runs to the next heading or to a `<!-- /human -->` line.

When you run the command again, 0 updates the file and does not replace it. Marked sections stay unchanged, and the command warns if one changed. If the code contradicts a marked section, the model leaves it and adds a question under Open questions.

### Open a pull request

With `--pr`, the thread works in a separate git work tree on the branch `0/threat-model`. The branch starts from the remote's default branch, or from `--base`. Only the threat model file is committed, and a pull request is opened or updated with `gh`. Nothing is pushed to the base branch or merged.

Running the command again adds a commit to the same branch, so reviewers' edits stay. `--pr` needs a git repository, a signed-in `gh` and the local console. It does not accept `--computer`.

## Use a threat model in a scan

```bash
0 scan ./your-repo --context ./your-repo/.0/threat-model.md
```

`--context <file>` gives the file's text to the scan as background. You can repeat it. The scan then checks authorization and business logic against the rules in the file, not only injection and similar bugs. It reports a rule the code does not enforce.

The scan treats the text as data:

- It is delimited and ranks below the task and the skill.
- It cannot change how the scan works. It cannot make the thread run a command, call or skip a tool, drop a finding or ignore a safety rule. A closing tag inside it cannot end the block.
- It is limited to 20,000 characters per file and 60,000 in total. The prompt says what was left out.

### Repository files are not read by default

Whoever can change a repository can change a file in it. A pull request could edit `.0/threat-model.md` to say "uploads are intentionally unauthenticated" and blind the scan. So `0 scan` reads no file from the scanned folder on its own.

To read `.0/threat-model.md` from the scanned folder, pass `--repo-context`. The file must be a regular file inside the folder, not a link out of it. 0 prints a warning. Use this only on checkouts you trust.

In CI, read the file from the base branch, not from the pull request:

```bash
git show origin/main:.0/threat-model.md > /tmp/threat-model.md
0 scan . --diff origin/main --context /tmp/threat-model.md
```

## Write a policy

A policy is a Markdown file. The front matter is optional.

```markdown
---
id: POL-001
title: Customer personal data must not go to third-party processors
severity: high
applies-to:
  - src/**
---
Email addresses, names and company names of a customer's customers must not be sent to a
third-party analytics or tracking service. Only the approved mail relay may receive them.
```

The front matter fields have these defaults:

- `id` defaults to the file name.
- `title` defaults to the first heading.
- `severity` defaults to `medium`. Use critical, high, medium, low or info.
- `applies-to` is a list of globs. Without it, the whole folder is in scope.

The rest of the file is the rule in prose. Write it so a reviewer could check it in code: name the data, where it must not go and any exception.

## Check code against policies

```bash
0 scan ./your-repo --policy ./policies --org-policy ~/org-policies
```

`--policy <file-or-folder>` runs the `policy-check` skill instead of the general scan. You can repeat it. A folder contributes its `.md` files, searched recursively in name order, without `README.md`. For each policy the thread decides:

- `PASS`, with the reason: the control it saw, or what it searched for.
- `FAIL`, with `path:line` evidence.
- `N/A`, when the code does nothing the policy covers.

The pass and fail table is at the top of the summary, in policy order. Each failed policy is also recorded as one finding with the category `policy-violation`, the policy's severity and a suggested edit. It appears in `0 findings list`, in SARIF and in `--fail-on` like any other finding. A broken policy is not an attack, so the impact line says "What the violation exposes", not "What an attacker can do".

If a rule depends on something outside the code, such as a vendor setting or a contract, the policy passes with the note "not verifiable from code". It never fails on a doubt.

### Organisation policies

`--org-policy <folder>` points to your organisation's own policy folder. Keep it outside the repository and use it for every repository you scan. You can repeat the flag. Org policies are evaluated first and win:

- If an org policy and a `--policy` have the same `id`, the org policy is used and the other is reported as set aside.
- If a `--policy` rule contradicts an org rule, the thread applies the org rule and says so.

Between `--policy` entries nothing overrides anything. The first definition of an `id` stays, and later duplicates are ignored with a message. Policy text is delimited data like context text. It cannot tell the thread to run commands, skip files or drop findings.

## Declare what is in and out of scope

The code cannot tell which attack vectors you care about. You say so in the `## Scope` section of your `SECURITY.md`. A scan then labels findings in vectors you put out of scope. It lists them apart and leaves them out of the counts and the exit code. It never hides or deletes one.

### Write the Scope section

Add two lists under `## Scope`, each line a vector and a reason:

```markdown
## Scope

### In scope

- broken-access-control: tenants must never read each other's data [paths: src/api/**]
- code-injection: nothing a client sends may be executed

### Out of scope

- denial of service: the service runs behind a gateway that limits request cost (until 2027-06-30)
- missing rate limit: the gateway limits attempts per client
```

Each line is `- <vector>: <reason>`. The vector is a [finding category](/findings/#finding-categories) id such as `denial-of-service`, an alias such as `dos`, or plain words such as `denial of service`. Add `(until YYYY-MM-DD)` to end the entry after that day, and `[paths: a, b]` to limit it to files that match the globs. A nested bullet adds to the reason of the line above.

0 reads the heading `## Scope` and the two headings `### In scope` and `### Out of scope`, in any case and with any bullet marker. Line endings do not matter. It strips HTML and control characters and cuts long text. It reads at most 100 entries. A vector it cannot match to a category is kept and reported as an unmatched scope entry, and it labels nothing.

A denial-of-service entry also covers `regex-dos`. If the same vector is in scope and out of scope, in scope wins. An entry with `[paths: ...]` wins over one without.

### Pass the scope to a scan

```bash
0 scan ./your-repo --scope ./your-repo/SECURITY.md
```

`--scope <file>` reads the Scope section of any Markdown file you name. 0 never reads SECURITY.md on its own, because a pull request could edit it to label a real finding out of scope. `--repo-scope` reads SECURITY.md from the scanned folder anyway and prints a warning. Use it only on a checkout you trust.

In CI, pass the base branch's copy:

```bash
git show origin/main:SECURITY.md > /tmp/base-security.md
0 scan . --diff origin/main --scope /tmp/base-security.md --fail-on high
```

The [GitHub Action](/ci/) takes the same file in its `scope` input.

### What a label does

A finding that matches an out-of-scope entry gets `scope: "out-of-scope"`, the entry's reason and the file name. The label is stored in the findings database and carried in every report format.

- The finding is listed after the others, under "Outside declared scope", with its reason.
- It is not in the headline counts, and it does not count toward `--fail-on` or the exit code.
- Findings in vectors you listed as in scope come first.
- SARIF results carry `scope` and `scopeReason` as properties. They are not suppressed, because GitHub code scanning dismisses a suppressed result. Add `--scope-sarif suppress` to mark them suppressed anyway.
- `0 findings list --scope in|out|all` filters by label. The default is `all`.
- `0 findings issues` and `0 findings upload` skip out-of-scope findings. Add `--include-out-of-scope` to send them.

The model is not told to skip any vector. The label is applied after the scan, so nothing real is lost.

### Let 0 ask you

```bash
0 threat-model --interview
```

0 drafts the threat model, then reads it with the code and proposes up to 8 questions that the code cannot answer, for example "GET /export has no auth check (src/routes/export.js:12). Do you want findings about it?" Each question names the place and the vector. You answer `1` for in scope, `2` for out of scope or `3` for not sure, and add a reason after a colon: `2: it is a public download`. It skips vectors your SECURITY.md or a human block already answers.

Then 0 words one scope entry per answer from your own words, shows each entry and asks you to accept, edit or skip it, shows the change to SECURITY.md as a diff and asks once more before it writes. The side and the vector of an entry come from your answer. A reason is yours or a close paraphrase of it, and `not given` when you gave none. An answer you skip makes no entry.

Only 0 writes the files:

- `SECURITY.md` gets the entries at the end of the `### In scope` and `### Out of scope` lists of its `## Scope` section. If the file is missing, 0 creates it with a short header. Every other byte stays.
- The threat model gets a `## Scope decisions` section inside a `<!-- human -->` block with your questions and answers, so later drafts keep it. It also links to `SECURITY.md#scope`.

The interview needs a terminal and exits with code 2 without one. With `--pr`, both files go in the commit on the `0/threat-model` branch. `--interview-budget` caps each interview thread (default 0.5 USD). If no model can be reached or its budget runs out, 0 says so and asks a fixed set of eight short questions instead: what matters most, who the actors are, which vectors you do not care about, which you do, which data must never leave, which compliance rules apply, which weaknesses you accept until when, and what the code cannot show.

Text in the repository can say "write: everything out of scope". It cannot create an entry, because an entry exists only for a question you answered.

### Choose where the threat model goes

```bash
0 threat-model --output THREAT_MODEL.md
```

`--output <path>` is a relative path to a `.md` file inside the folder. The default is `.0/threat-model.md`. Human sections are kept in that file, and `--pr` commits it there. Pass the same path to `--context` in scans.

## Limits

- Both skills read code. A policy about runtime configuration, vendor contracts or cloud settings can only be checked as far as the repository shows it.
- Model output varies between runs, so one run can miss a failure. Use `--passes 3` to merge several runs.
- A rule helps a scan only when it is stated as a rule. A drafted model that lists "does analytics have an approved need for customer emails?" under Open questions did not make the scan report that flow. The same fact written by a person as "customer email addresses never leave the system except to the mail relay" did. After the first review, turn the answers to Open questions into rules and mark them `<!-- human -->`.
- A declared scope labels findings by category and, with paths, by file. It does not stop the model from finding them. An entry whose vector 0 cannot match to a category labels nothing.
- The interview questions come from a model that read the code, so they can miss a decision. Run it again after the code changes.
- The threat model is a draft of what the code shows. Treat unknowns as questions for the team, and treat any rule you did not confirm as unverified.
