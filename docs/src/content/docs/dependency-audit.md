---
title: Dependency audit
description: Check the packages your project uses for known advisories, malicious packages, license problems and newer versions, with an SBOM.
---

A dependency audit checks the packages your project uses. You build a software bill of materials (SBOM) from your lockfiles, then run checks on it. No check needs a model key.

## Generate an SBOM

```bash
0security sbom generate . -o sbom.cdx.json
```

The default generator reads lockfiles as text. It installs and runs nothing, and it makes no network request. It reads npm, pnpm, yarn, Cargo, Go, Python, Ruby, PHP, .NET, Maven, Gradle, Dart and Elixir files. The output is CycloneDX 1.5, sorted, so the same lockfiles give the same file.

For SPDX 2.3 JSON, add `--format spdx`. To describe a container image, use `--generator syft` or `trivy` with `--image`. See [sbom generate](/commands/#sbom-generate) for every option.

The SBOM lists what it could not resolve, such as a version range or a parent POM outside the repository. `sbom check` prints that count, so a gap is visible.

### Resolve Maven and Gradle dependencies

For Maven and Gradle, the build lists the transitive packages. Read a report you already made, with no build and no network:

```bash
0security sbom generate . --resolve-from tree.txt -o sbom.cdx.json
```

Or let 0 run your own `mvn` or `gradle`:

```bash
0security sbom generate . --resolve --allow-build-tools -o sbom.cdx.json
```

`--resolve` runs the project's build scripts and downloads from the repositories the build names. It asks first, and `ZERO_ENTERPRISE` refuses it.

## Check for advisories and malicious packages

```bash
0security sbom check sbom.cdx.json
```

Every component is looked up in the public OSV database at `api.osv.dev`, by package URL. Each advisory shows its severity and the lowest version that fixes it. A package that OSV lists as malicious (an id starting `MAL-`) is shown as critical.

The command exits 1 when it finds any advisory, so a scheduled job can fail. Add `--format sarif -o deps.sarif` to write a file that [findings import](/findings/#import-findings-from-another-scanner) accepts, or `--format json` for scripts.

The malicious-package check is OSV's own records. 0 does not analyze package contents.

## Check an SBOM from another tool

For an ecosystem 0security cannot generate an SBOM for, make a CycloneDX JSON file with another generator, then check it:

```bash
0security sbom check other-tool.cdx.json
```

`sbom check` reads any CycloneDX JSON file with a `components` array. Each component needs a `purl` (package URL) such as `pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1`, and the version must be in the purl. A component with no `purl`, or one that is not a `pkg:` URL, is skipped without a message. If no component has one, the command stops with an error. Check that the `resolved` count at the end of the output matches the components you expect.

A file with a log4j-core 2.14.1 component, an npm component with no known advisory and one component with no `purl` reported 8 advisories for log4j-core and `resolved 2`. The `--outdated` and `--registry` options and SARIF output were not tried on such a file. SPDX files are not read.

## List packages with a newer version

```bash
0security sbom check sbom.cdx.json --outdated
```

This looks up each package at `api.deps.dev` and lists the ones with a newer version. It covers npm, PyPI, Cargo, Go, NuGet, Maven and RubyGems, at most 200 components, runtime dependencies first. A newer version is information. It never changes the exit code.

## Check licenses

```bash
0security sbom licenses . --preset no-copyleft
0security sbom licenses sbom.cdx.json --deny 'GPL-*,AGPL-*' --format sarif > licenses.sarif
```

The argument is an SBOM or a folder. Licenses come from the SBOM, which holds what lockfiles state. A component with no license is unknown, and `--unknown fail` turns that into a failure. Use `--policy` for a file of allow and deny lists with per-package exceptions.

Add `--resolve` to look up unknown licenses at `api.deps.dev`. This sends package names and versions. The output is information from lockfiles and registries, not legal advice.

## Is the vulnerable library used?

`sbom check --usage` adds import evidence to each Maven advisory. Point it at the folder with your Java, Kotlin, Scala or Groovy source:

```bash
0security sbom check sbom.cdx.json --usage .
```

Each Maven advisory gets one of five labels:

- imported: application code has an import of a package of the component.
- symbol-imported: application code imports or writes out in full a class that the advisory lists as vulnerable.
- test-only: only test code imports the component.
- not-imported: no import was found in the scanned source. A transitive or reflection use is not ruled out.
- unknown: the scan did not cover all your source, so 0 makes no statement.

Each label lists up to 10 files and lines. The JSON output has a `usage` field on each advisory, and SARIF results have a `usage` property.

The label is evidence and never a verdict. An import shows that a package is named, not that a vulnerable method runs. No label means the code is unreachable, and no label changes a severity. Advisories for other ecosystems get no label.

Most OSV records for Maven do not list vulnerable classes, so symbol-imported is rare. When a record lists them in `imports` under `ecosystem_specific` or `database_specific`, 0 looks for those classes in imports and in fully qualified uses. A class used through a wildcard import or reflection is missed.

The exit code stays 1 when any advisory is found. To leave not-imported advisories out of the exit code, add `--ignore-not-imported`. They are still listed. Malicious packages always count. 
The scan has limits on depth, files, bytes and folder entries. A file over the size cap, an unreadable folder and a symbolic link are skipped. Build output, vendored and tool folders (build, target, out, dist, vendor, node_modules, .git and similar) are not read. One that holds a source file counts as not scanned. Hidden folders are read. When an advisory lists vulnerable classes, a source line over 4000 characters is not searched and counts as a limit. When any limit is reached or anything is skipped, the output says so, for example `Scan limit reached: 20 files not scanned.` Every advisory that would be not-imported is then marked unknown. An advisory whose record lists more vulnerable symbols than 0 searches is marked unknown too. `--ignore-not-imported` never ignores unknown, so those advisories still set the exit code.

```bash
0security sbom check sbom.cdx.json --usage . --ignore-not-imported
```

Source files are read as text, with limits on depth, file count and file size. Symbolic links are not followed. Nothing runs, and the scan sends nothing. Only the OSV lookup from `sbom check` goes out, as without `--usage`.

Not tested: Kotlin, Scala and Groovy sources beyond import lines, and records from OSV that list vulnerable classes for Maven.

To list every import without checking advisories, run `sbom java-usage`:

```bash
0security sbom java-usage sbom.cdx.json .
```

For an estimate with a model, run the experimental `dependency-reachability` skill. See [Dependencies](/findings/#dependencies).

## Fix and track results

Import the SARIF file to keep advisories in your findings list, then bump a package:

```bash
0security findings import deps.sarif
0security findings fix 3f2a --test "npm test"
```

The fix raises the package to the lowest fixed version. See [Fix a finding](/findings/#fix-a-finding).

## Run it on a schedule

The GitHub Action has an `sbom` mode with an optional license preset. See [SBOM mode](/ci/#sbom-mode). Without the Action, run the commands above in any scheduled job, as in [Keep an SBOM and check it for advisories](/ci/#keep-an-sbom-and-check-it-for-advisories).

## Network use

| Command | Destination | What is sent |
| --- | --- | --- |
| `sbom generate` | None | Nothing. |
| `sbom generate --resolve` | The repositories your build names | Whatever your own `mvn` or `gradle` sends. |
| `sbom generate --image` | Set by syft or trivy | Whatever that tool sends to pull the image. |
| `sbom check` | `api.osv.dev` | Package URLs. |
| `sbom check --outdated` | `api.deps.dev` | Package names. |
| `sbom licenses --resolve` | `api.deps.dev` | Package names and versions of components with no license. |
| `findings evidence --check-advisories` | `api.osv.dev` | Package URLs. |
| `sbom check --usage`, `sbom java-usage`, `sbom licenses` without `--resolve` | None | Nothing. |

With `ZERO_ENTERPRISE=1`, the OSV and deps.dev lookups and `--resolve` are refused. `--resolve-from` still works. See [Data flow](/data-flow/) for every destination.

## What a dependency audit does not do

- It reads lockfiles and manifests. It misses vendored code and system packages unless you use syft or trivy.
- It does not show that a vulnerable function is called. A clean result is not proof that the project is safe. See [Is the vulnerable library used?](#is-the-vulnerable-library-used).
- It does not check private registries or advisories that OSV does not list.
- Model files are a separate check. See [AI security](/ai-security/).
