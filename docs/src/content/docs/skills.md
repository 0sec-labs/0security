---
title: Skills
description: Give the agent reusable instructions with standard skill folders.
---

A skill is a folder of instructions the agent loads when a task calls for it. It is not code. Add skills to teach the agent your methods.

[Extensions](/extensions/) connect 0 to your tools and services, such as GitHub, MCP servers and rules. An extension can include a skill that explains how to use it. CLI commands are fixed entry points, not skills.

## Add a skill

1. Run `0security` and open **Skills** in the sidebar.
2. Press **Browse** to add a skill from GitHub, **New skill** to write one, or **Import** to bring one in.
3. Ask the agent to use the skill, or let it find the skill itself.

The **Installed** tab lists your own skills first, then the bundled guides. The agent loads a skill with `load_skill`.

## Manage skills from the command line

Every action on the Skills page has a command. With the console running, commands go through it. Otherwise they use the same files directly.

```sh
0security skills list
0security skills catalog --search handoff
0security skills add mattpocock~skills~handoff --yes
0security skills add ./my-skill --yes
0security skills import ./code-review
0security skills edit code-review --file ./SKILL.md
0security skills export code-review -o code-review.skill.json
0security skills link ~/team-skills
0security skills delete code-review --yes
0security scan . --skill my-skill
```

`skills add` accepts an Agent Skills folder (a `SKILL.md` with name and description front matter, plus optional scripts and references) or a git repository. It shows what the skill can do before it installs. `--yes` installs and enables it, then prints the skill id, its files and the scripts it bundles. `skills import` takes a folder with `SKILL.md` or an exported bundle. `skills link` mounts a folder without copying it.

## Use an installed skill in a scan

Pass a skill to `0security scan` with `--skill`. A bare name such as `my-skill` is looked up once, when the scan starts, among the skills you installed. A full id such as `extension/my-skill/my-skill` names exactly one skill. If two installed skills share a name, 0 stops and lists their ids.

```sh
0security scan . --skill my-skill
```

You choose the skill. The text of its `SKILL.md` goes to the model as instructions, so install only skills you have read. Bundled scripts do not run when a skill is installed or loaded. The model can run one only after you approve it.

A skill allow-list on a Sentinel matches full ids only. `scan` allows the built-in `scan` skill and not an installed skill that is also named `scan`.

## Folder format

0 reads the [Agent Skills format](https://agentskills.io/specification):

```text
code-review/
  SKILL.md
  scripts/
  references/
  assets/
```

`SKILL.md` starts with YAML front matter containing `name` and `description`, followed by Markdown instructions. The other folders are optional. Resource paths resolve inside the skill folder. Mounting or importing a skill never runs its scripts.

```markdown
---
name: code-review
description: Review application code for security issues. Use for source reviews.
---

Trace input through the application and verify each finding against its caller.
```

## Where skills come from

0 finds skills in `.agents/skills` folders in the project and in your home directory. It also reads `.claude/skills` for compatibility. **Mount folder** adds another folder on the computer without copying it, and changes to the original files appear automatically.

Local users and team owners can edit mounted, personal and project skills in place. Team editors edit a workspace copy instead.

## Edit, import and export

- **New skill** creates a workspace skill. **Edit** changes its instructions.
- **Customize** copies a built-in guide, or a folder you cannot write to, into an editable skill and keeps its supporting files.
- **Import** takes a `SKILL.md` file, a skill folder (with its references, scripts and assets) or an exported skill.
- **Export** downloads `SKILL.md`, or every file as a bundle that another 0 workspace can import. Other agents cannot read the bundle directly.

Saves check the revision. If someone changes a skill while you edit, the save is rejected and your draft stays open. Press **Reload latest** to replace the draft with the current version.

## Skills that check their own work

A skill can declare a `verify:` block in the front matter of its `SKILL.md`. The block sets:

- the command to run
- a container image pinned by digest
- whether the network stays off
- a timeout
- what counts as success: exit 0, a pattern, or no worse than before
- optionally, a planted marker the check must flag

When a thread runs such a skill, 0 runs the check after the agent finishes. The thread then shows **Verified by** or **Not verified** with the reason. Only built-in skills run their check today. The built-in `workflow-hardening` skill pins GitHub Actions to commit SHAs, narrows permissions and moves untrusted expressions into `env`.

## Teams

In a team workspace, skills you create or import are shared with the team. Editors can create and edit them, and viewers can browse and export them. Only owners can mount host folders. Team workspaces do not use the host operator's personal skill folders.

## Adding skills from GitHub

A skill is text the agent follows with your permissions, so adding one carries the same risk as adding an extension. **Skills → Browse** and **Add from GitHub repository** protect you in these ways:

- 0 resolves the repository to a full commit SHA and reads the skill folder at that commit with your own `gh` login.
- 0 checks every file against its git object id.
- You see the real `SKILL.md`, the file list, the licence and the commit before you click to add. 0 flags hidden Unicode, HTML comments and long encoded blocks.
- Scripts in a skill folder are stored but never run.
- Symbolic links and submodules are refused. `SKILL.md` is limited to 128 KiB, and a folder to 128 files and 4 MiB.
- 0 never overwrites an existing skill.

A skill stays at the commit you added until you preview and add a newer one. 0 stores the provenance next to the skill and writes each add or removal to the audit log. Skills without a permissive licence are listed with **View on GitHub** and are not copied.

Folder mounting works with local thread execution. Mounted skills are not copied into SmolVM guests automatically.

## Next steps

- [Security model](/configuration/#security-model): what protects you from third-party code and text.
- [Sentinels](/sentinels/): choose the skills a Sentinel loads.
- [Extensions](/extensions/): add tools, not only instructions.
