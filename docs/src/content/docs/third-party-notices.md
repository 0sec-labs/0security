---
title: Third-party notices
description: Attribution and licenses for the color palettes, brand logos and skill owner avatars bundled in the browser app, and for the grammars and Rust crates built into the foxguard binary.
---

The browser app has ten color themes under Settings, Appearance. Zero is our own. The other nine use palette color values (a few hex codes each) from the projects below. Each is MIT licensed, and its copyright line is reproduced here as the license requires. The full text is in the `LICENSE` file at each source.

| Theme | Copyright | License | Source |
|---|---|---|---|
| Dracula (and Alucard) | Copyright (c) 2023 Dracula Theme | MIT | [dracula/dracula-theme](https://github.com/dracula/dracula-theme/blob/main/LICENSE) |
| Nord | Copyright (c) 2016-present Sven Greb | MIT | [nordtheme/nord](https://github.com/nordtheme/nord/blob/develop/license) |
| Solarized | Copyright (c) 2011 Ethan Schoonover | MIT | [altercation/solarized](https://github.com/altercation/solarized/blob/master/LICENSE) |
| Catppuccin (Mocha, Latte) | Copyright (c) 2021 Catppuccin | MIT | [catppuccin/catppuccin](https://github.com/catppuccin/catppuccin/blob/main/LICENSE) |
| Tokyo Night (Night, Day) | Copyright (c) 2018-present Enkia | MIT | [tokyo-night/tokyo-night-vscode-theme](https://github.com/tokyo-night/tokyo-night-vscode-theme/blob/master/LICENSE.txt) |
| Rosé Pine (Main, Dawn) | Copyright (c) 2023 Rosé Pine | MIT | [rose-pine/rose-pine-theme](https://github.com/rose-pine/rose-pine-theme/blob/main/LICENSE) |
| One (Atom One Dark, Light) | Copyright (c) 2016 GitHub Inc. | MIT | [atom/one-dark-syntax](https://github.com/atom/one-dark-syntax/blob/master/LICENSE.md) |
| GitHub (Dark, Light) | Copyright (c) 2020 Primer | MIT | [primer/github-vscode-theme](https://github.com/primer/github-vscode-theme/blob/main/LICENSE) |
| Gruvbox | Copyright (c) 2018 Pavel Pertsev | MIT | [gruvbox-community/gruvbox](https://github.com/gruvbox-community/gruvbox/blob/master/LICENSE.md) |

Gruvbox is credited to the MIT-licensed community fork; the original
(morhetz/gruvbox) states MIT/X11 in its README but has no license file.

## MIT license

Permission is hereby granted, free of charge, to any person obtaining a copy of
the palettes and associated documentation files (the "Software"), to deal in the
Software without restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the
Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Brand logos and skill owner avatars

Logos and avatars are bundled with the app and served from the same origin. The browser never contacts a third-party image host for them.

| What | Source | Terms |
|---|---|---|
| Skill owner avatars | GitHub profile pictures of the nine publishers in the skills directory, downloaded once at 88 px by `scripts/refresh-skills-catalog.mjs` and embedded in `skills-catalog.generated.json` | Shown as attribution next to those owners' public skills. Avatars and names belong to their owners. |

## Foxguard

The foxguard binary, built from `crates/foxguard`, is available under MIT OR Apache-2.0. It bundles tree-sitter grammars and Rust crates.

The grammars are vendored in `crates/foxguard/vendor`. Each keeps its own MIT `LICENSE` file.

| Grammar | Copyright | License |
|---|---|---|
| tree-sitter-bash | Copyright (c) 2017 Max Brunsfeld | MIT |
| tree-sitter-c | Copyright (c) 2014 Max Brunsfeld | MIT |
| tree-sitter-javascript | Copyright (c) 2014 Max Brunsfeld | MIT |
| tree-sitter-typescript (typescript and tsx) | Copyright (c) 2017 Max Brunsfeld | MIT |

`crates/foxguard/THIRD-PARTY-LICENSES.md` lists every Rust crate built into the binary with its version, license and source. Regenerate it with `node scripts/generate-rust-notices.mjs` after a dependency change.
