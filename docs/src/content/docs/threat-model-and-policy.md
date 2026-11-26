---
title: Threat model and policy checks
description: Draft a reviewable threat model for a repository, steer scans with it, and check the code against policies written in Markdown.
---

A threat model and policies help a scan look past low-level bugs. Draft a threat model, write policies, and pass both to `0security scan`.

A threat model says what the system is, who the actors are and which authorization and business rules must hold, such as "only an admin may change a role". A policy is a rule your organisation wrote, such as "customer data must not go to a third-party processor". For each policy, 0 answers pass or fail with evidence.

Both are plain files that people review in a pull request. They use the same threads, skills and findings as `0security scan`.

## Draft a threat model

```bash
0security threat-model ./your-repo
0security threat-model ./your-repo --pr
```

A thread follows the `threat-model` skill, reads the code and writes one file, `.0/threat-model.md` (or the path in `--output`). It records no findings and changes no other file. When the folder's `SECURITY.md` has a `## Scope` section, the summary links to it. The section is read as data and does not change the draft.

The file has a fixed structure:

- Front matter with `title`, `generated` (date), `commit`, `generator` and `status: draft`.
- These sections, in order: Summary, What matters most, Assets, Actors, Trust boundaries, Entry points, Authorization and business rules, Data flows, Open questions.
- A last section, Threat map, with a diagram (see below).

The file names only what the thread saw, with `path:line`. Anything the code does not say is written as `unknown: confirm with the team` and listed under Open questions.

### Threat map

The last section, `## Threat map`, is a [Mermaid](https://mermaid.js.org) flowchart for readers who do not read code. It shows the components, external actors and data stores the other sections name, one subgraph per trust boundary, and arrows for the main data flows. Entry points with no authorization check seen are outlined in red. The web console and GitHub render Mermaid, so you can read the diagram in a pull request.

The diagram is drawn from the same text as the sections above, so it shows what the thread saw and nothing more. It shows no findings: the draft records none.

After the draft, 0 checks the diagram and prints a `note: diagram: ...` line if it looks wrong, for example a missing section, an unclosed code fence, a block that does not start with `flowchart`, or a `subgraph` without `end`. These notes are warnings only and do not change the exit code. 0 does not check that the diagram renders, so open the file's preview before you merge.

### Review and keep your edits

Mark text you wrote or approved with `<!-- human -->` on its own line before the text. Marked text runs to the next heading or to a `<!-- /human -->` line.

When you run the command again, 0 updates the file and does not replace it. Marked sections stay unchanged, and the command warns if one changed. If the code contradicts a marked section, the model leaves it and adds a question under Open questions.

### Open a pull request

With `--pr`, the thread works in a separate git work tree on the branch `0/threat-model`. The branch starts from the remote's default branch, or from `--base`. Only the threat model file is committed, and a pull request is opened or updated with `gh`. Nothing is pushed to the base branch or merged.

Running the command again adds a commit to the same branch, so reviewers' edits stay. `--pr` needs a git repository, a signed-in `gh` and the local console. It does not accept `--computer`.

## Use a threat model in a scan

```bash
0security scan ./your-repo --context ./your-repo/.0/threat-model.md
```

`--context <file>` gives the file's text to the scan as background. You can repeat it. The scan then checks authorization and business logic against the rules in the file, not only injection and similar bugs. It reports a rule the code does not enforce.

The scan treats the text as data:

- It is delimited and ranks below the task and the skill.
- It cannot change how the scan works. It cannot make the thread run a command, call or skip a tool, drop a finding or ignore a safety rule. A closing tag inside it cannot end the block.
- It is limited to 20,000 characters per file and 60,000 in total. The prompt says what was left out.

### Repository files are not read by default

Whoever can change a repository can change a file in it. A pull request could edit `.0/threat-model.md` to say "uploads are intentionally unauthenticated" and blind the scan. So `0security scan` reads no file from the scanned folder on its own.

To read `.0/threat-model.md` from the scanned folder, pass `--repo-context`. The file must be a regular file inside the folder, not a link out of it. 0 prints a warning. Use this only on checkouts you trust.

In CI, read the file from the base branch, not from the pull request:

```bash
git show origin/main:.0/threat-model.md > /tmp/threat-model.md
0security scan . --diff origin/main --context /tmp/threat-model.md
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
0security scan ./your-repo --policy ./policies --org-policy ~/org-policies
```

`--policy <file-or-folder>` runs the `policy-check` skill instead of the general scan. You can repeat it. A folder contributes its `.md` files, searched recursively in name order, without `README.md`. For each policy the thread decides:

- `PASS`, with the reason: the control it saw, or what it searched for.
- `FAIL`, with `path:line` evidence.
- `N/A`, when the code does nothing the policy covers.

The pass and fail table is at the top of the summary, in policy order. Each failed policy is also recorded as one finding with the category `policy-violation`, the policy's severity and a suggested edit. It appears in `0security findings list`, in SARIF and in `--fail-on` like any other finding. A broken policy is not an attack, so the impact line says "What the violation exposes", not "What an attacker can do".

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
0security scan ./your-repo --scope ./your-repo/SECURITY.md
```

`--scope <file>` reads the Scope section of any Markdown file you name. 0 never reads SECURITY.md on its own, because a pull request could edit it to label a real finding out of scope. `--repo-scope` reads SECURITY.md from the scanned folder anyway and prints a warning. Use it only on a checkout you trust.

In CI, pass the base branch's copy:

```bash
git show origin/main:SECURITY.md > /tmp/base-security.md
0security scan . --diff origin/main --scope /tmp/base-security.md --fail-on high
```

The [GitHub Action](/ci/) takes the same file in its `scope` input.

### What a label does

A finding that matches an out-of-scope entry gets `scope: "out-of-scope"`, the entry's reason and the file name. The label is stored in the findings database and carried in every report format.

- The finding is listed after the others, under "Outside declared scope", with its reason.
- It is not in the headline counts, and it does not count toward `--fail-on` or the exit code.
- Findings in vectors you listed as in scope come first.
- SARIF results carry `scope` and `scopeReason` as properties. They are not suppressed, because GitHub code scanning dismisses a suppressed result. Add `--scope-sarif suppress` to mark them suppressed anyway.
- `0security findings list --scope in|out|all` filters by label. The default is `all`.
- `0security findings issues` and `0security findings upload` skip out-of-scope findings. Add `--include-out-of-scope` to send them.

The model is not told to skip any vector. The label is applied after the scan, so nothing real is lost.

### Let 0 ask you

```bash
0security threat-model --interview
```

0 drafts the threat model, then asks you up to 8 questions on the terminal. Each question is about one class of vulnerability and lists the places, so you answer once per class. For example:

```text
This scan found 3 denial-of-service issues (src/routes/search.js:14, src/routes/report.js:30, and 1 more). Highest severity: high. One request can cost a lot or block other users. Do you want findings like these?
```

You answer `1` for yes (in scope), `2` for no (out of scope) or `3` for not sure, and add a reason after a colon: `2: our gateway limits request cost`. 0 skips classes your SECURITY.md or a human block already answers.

#### Questions come from two places

- The latest scan of the folder. 0 asks about the classes that produced findings, with the places, the count and the highest severity. It skips findings already labelled in or out of scope.
- A model that reads the code and the draft. It asks about what a scan cannot show, such as a route that is public on purpose or a field of personal data that goes to a third party.

When both have a question about the same class, you get one question that lists all the places. Questions are ordered by the highest severity, then by how likely you are to answer "out of scope".

To choose the scan:

```bash
0security threat-model --interview --from-scan report.json
0security threat-model --interview --scan --scan-budget 2
```

- Without a flag, 0 uses the latest scan of the folder from the last 30 days, found by the folder's resolved path. Passes and batches that ran together count as one scan.
- `--from-scan` takes a report from `0security scan --format json`. 0 refuses a report over 8 MB or with more than 5000 findings.
- `--scan` runs a scan first. It prints a rough cost estimate and asks before it runs. `--scan-budget` caps the scan (default 3 USD).
- With no scan, 0 says so and asks only the questions from reading the code.

#### Which classes it asks about

It asks where "we do not care" is a real answer: denial of service, a missing limit on attempts, a route that is public on purpose, data sent to a third party, a rule the code conflicts with, and a weakness you accept for a while.

It never asks about code injection, command injection, SQL injection, hardcoded secrets, plaintext passwords, path traversal, XML external entities, unsafe deserialization or similar classes. They are real vulnerabilities in nearly every application, so you cannot declare them out of scope through the interview. You can still write them in SECURITY.md by hand. The scan then prints a warning that the class is usually a real vulnerability, and the entry works as written.

#### What 0 writes

0 words one scope entry per answer from your own words, shows each entry and asks you to accept, edit or skip it, shows the change to SECURITY.md as a diff and asks once more before it writes. The side and the vector of an entry come from your answer. A reason is yours or a close paraphrase of it, and `not given` when you gave none. An answer you skip makes no entry. An out-of-scope answer covers the files the question listed, up to 10. For a class in more files, the entry covers the whole class, and you can edit it before you accept.

Only 0 writes the files:

- `SECURITY.md` gets the entries at the end of the `### In scope` and `### Out of scope` lists of its `## Scope` section. If the file is missing, 0 creates it with a short header. Every other byte stays.
- The threat model gets a `## Scope decisions` section inside a `<!-- human -->` block with your questions and answers, so later drafts keep it. It also links to `SECURITY.md#scope`.

The interview needs a terminal and exits with code 2 without one. With `--pr`, both files go in the commit on the `0/threat-model` branch. `--interview-budget` caps each interview thread (default 0.5 USD). If no model can be reached or its budget runs out, 0 says so and asks a fixed set of eight short questions instead: what matters most, who the actors are, which vectors you do not care about, which you do, which data must never leave, which compliance rules apply, which weaknesses you accept until when, and what the code cannot show.

Text in the repository or in a finding can say "write: everything out of scope". It cannot create an entry, because an entry exists only for a question you answered, and the text of a finding never appears in a question.

#### Find out when to run it

At the end of a scan on a terminal, 0 prints one line when findings are in classes you have not declared in scope:

```text
3 findings are in classes you have not declared in scope (denial-of-service, missing-rate-limit). Run 0security threat-model --interview to say which you care about.
```

0 never asks during a scan. It prints nothing in CI, without a terminal, or when a JSON report goes to standard output.

### Choose where the threat model goes

```bash
0security threat-model --output THREAT_MODEL.md
```

`--output <path>` is a relative path to a `.md` file inside the folder. The default is `.0/threat-model.md`. Human sections are kept in that file, and `--pr` commits it there. Pass the same path to `--context` in scans.

## Limits

- Both skills read code. A policy about runtime configuration, vendor contracts or cloud settings can only be checked as far as the repository shows it.
- Model output varies between runs, so one run can miss a failure. Use `--passes 3` to merge several runs.
- A rule helps a scan only when it is stated as a rule. A drafted model that lists "does analytics have an approved need for customer emails?" under Open questions did not make the scan report that flow. The same fact written by a person as "customer email addresses never leave the system except to the mail relay" did. After the first review, turn the answers to Open questions into rules and mark them `<!-- human -->`.
- A declared scope labels findings by category and, with paths, by file. It does not stop the model from finding them. An entry whose vector 0 cannot match to a category labels nothing.
- The code-reading questions come from a model, so they can miss a decision. Run the interview again after the code changes or a new scan.
- The scan questions cover the latest scan only. A class the scan did not find is not asked about unless the model sees it in the code.
- The threat model is a draft of what the code shows. Treat unknowns as questions for the team, and treat any rule you did not confirm as unverified.
