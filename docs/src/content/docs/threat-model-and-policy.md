---
title: Threat model and policy checks
description: Draft a reviewable threat model for a repository, steer scans with it, and check the code against policies written in Markdown.
---

Two things help a scan look past low-level bugs. A **threat model** says what the system is, who the actors are and which authorization and business rules must hold ("only an admin may change a role"). **Policies** are rules your organisation wrote ("customer data must not go to a third-party processor"), and `0` answers pass or fail for each with evidence.

Both are plain files that people review in a pull request. Neither is a new service: they use the same threads, skills and findings as `0 scan`.

## Draft a threat model

```
0 threat-model ./your-repo
0 threat-model ./your-repo --pr
```

A thread follows the `threat-model` skill, reads the code and writes one Markdown file, `.0/threat-model.md`. It records no findings and changes no other file. The structure is fixed:

- Front matter: `title`, `generated` (date), `commit`, `generator`, `status: draft`.
- Sections, in order: Summary, What matters most, Assets, Actors, Trust boundaries, Entry points, Authorization and business rules, Data flows, Open questions.
- It names only what it saw, with `path:line`. Anything the code does not say is written as `unknown: confirm with the team` and listed under Open questions.

Review it like any document. **Mark what you wrote or approved with `<!-- human -->`** on a line of its own before the text (the marked text runs to the next heading or a `<!-- /human -->` line). When you run the command again the file is updated, not replaced: marked sections are kept unchanged, and the command warns if one changed. If the code contradicts a human section the model leaves it and adds a question under Open questions.

With `--pr`, the thread works in a separate git work tree on the branch `0/threat-model` (from the remote's default branch, or `--base`), only that one file is committed and a pull request is opened or updated with `gh`. Nothing is pushed to the base branch and nothing is merged. Running it again adds a commit to the same branch, so reviewers' edits are kept. `--pr` needs a git repository, `gh` signed in and the local console, so it does not accept `--computer`.

## Use it in a scan

```
0 scan ./your-repo --context ./your-repo/.0/threat-model.md
```

`--context <file>` (repeatable) gives the file's text to the scan thread as background. The scan then weighs authorization and business logic against the rules the file states, not only injection and similar bugs, and reports a rule the code does not enforce. The text is:

- clearly delimited and marked as data of lower priority than the task and the skill;
- unable to change how the scan works: it cannot make the thread run a command, call or skip a tool, drop a finding or ignore a safety rule, and a closing tag inside it cannot end the block;
- bounded: 20,000 characters per file and 60,000 in total, and the prompt says what was left out.

### Why nothing is read from the repository by default

A file inside the repository under scan is written by whoever can change that repository. A pull request could edit `.0/threat-model.md` to say "uploads are intentionally unauthenticated" and blind the scan. So `0 scan` reads **no** file from the scanned folder on its own.

`--repo-context` is the explicit opt-in: it reads `.0/threat-model.md` from the scanned folder (a regular file inside it, never a link out of it) and prints a warning. Use it for your own trusted checkouts. **In CI, read the file from the base branch, not from the pull request head:**

```
git show origin/main:.0/threat-model.md > /tmp/threat-model.md
0 scan . --diff origin/main --context /tmp/threat-model.md
```

## Write policies

A policy is a Markdown file. The front matter is optional:

```
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

`id` defaults to the file name, `title` to the first heading, `severity` to `medium` (one of critical, high, medium, low, info). `applies-to` is a list of globs; without it the whole folder is in scope. The rest of the file is the rule in prose. Write it as something a reviewer could check in code: name the data, the place it must not go and any exception.

## Check against policies

```
0 scan ./your-repo --policy ./policies --org-policy ~/org-policies
```

`--policy <file-or-folder>` (repeatable) runs the `policy-check` skill instead of the general scan. A folder contributes its `.md` files, searched recursively in name order, without `README.md`. For each policy the thread decides:

- `PASS`, with the reason (the control it saw, or what it searched for);
- `FAIL`, with `path:line` evidence;
- `N/A`, when the code does nothing the policy is about.

The pass/fail table is at the top of the summary, in the order of the policies. Each failed policy is also recorded as one finding with the category `policy-violation`, the policy's severity and a suggested edit, so it appears in `0 findings`, in SARIF and in `--fail-on` like any other finding. Because a broken policy is not an attack, the impact line of these findings reads "What the violation exposes", not "What an attacker can do". A rule that depends on something outside the code (a vendor setting, a contract) is passed with a note "not verifiable from code", never failed on a doubt.

### Organisation policies

`--org-policy <folder>` (repeatable) is the organisation's own folder, kept outside the repository and used for every repository you scan. Its policies are evaluated first and win:

- an org policy and a `--policy` with the same `id`: the org one is used and the other is reported as set aside;
- a `--policy` rule that contradicts an org rule: the prompt tells the thread to apply the org rule and say so.

Between `--policy` entries nothing overrides anything: the first definition of an `id` stays and later duplicates are ignored with a message. Policy text, like context text, is delimited data: it cannot instruct the thread to run commands, skip files or drop findings.

## Limits

- Both skills read code. A policy about runtime configuration, vendor contracts or cloud settings can only be checked as far as the repository shows it.
- Model output varies between runs; a single run can miss a failure. `--passes 3` merges several runs.
- A rule helps a scan only when it is stated as a rule. A drafted model that lists "does analytics have an approved need for customer emails?" under Open questions did not make the scan report that flow, while the same fact written by a person as "customer email addresses never leave the system except to the mail relay" did. After the first review, turn the answers to Open questions into rules and mark them `<!-- human -->`.
- The threat model is a draft of what the code shows. Treat the unknowns as questions for the team, and treat any rule you did not confirm as unverified.
