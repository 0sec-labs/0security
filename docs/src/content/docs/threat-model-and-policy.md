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

A thread follows the `threat-model` skill, reads the code and writes one file, `.0/threat-model.md`. It records no findings and changes no other file.

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

## Limits

- Both skills read code. A policy about runtime configuration, vendor contracts or cloud settings can only be checked as far as the repository shows it.
- Model output varies between runs, so one run can miss a failure. Use `--passes 3` to merge several runs.
- A rule helps a scan only when it is stated as a rule. A drafted model that lists "does analytics have an approved need for customer emails?" under Open questions did not make the scan report that flow. The same fact written by a person as "customer email addresses never leave the system except to the mail relay" did. After the first review, turn the answers to Open questions into rules and mark them `<!-- human -->`.
- The threat model is a draft of what the code shows. Treat unknowns as questions for the team, and treat any rule you did not confirm as unverified.
