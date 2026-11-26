# Licensing

Everything in this repository is available under MIT OR Apache-2.0, at your option, except the contents of the `enterprise/` directory. That directory is licensed under the 0security Enterprise License in `enterprise/LICENSE`.

The enterprise code may be read and, for evaluation and development, run. Production use needs a license key. Contributions are not accepted for that directory. Third-party components keep their own licenses.

The rest of the repository can be used and run without infringing the Enterprise License.

## What is open and what is not

| Part | License | What you can do |
| --- | --- | --- |
| Core: CLI, engine, Foxguard static analyzer (`crates/foxguard`), web console, GitHub Action, SBOM, evidence, the verifiers `audit-verify` and `evidence verify`, OIDC | MIT OR Apache-2.0 | Use, change and redistribute, in production too. |
| The `enterprise/` folder: license key, shared findings server, roles (RBAC), SCIM, SAML, signed evidence, audit chain retention | 0security Enterprise License (source-available) | Read and modify it. Run it for development and testing. Production use needs a license key. |

The `enterprise/` folder is source-available, not open source. Features already in the open core will not move into `enterprise/`.

- [LICENSE-MIT](LICENSE-MIT)
- [LICENSE-APACHE](LICENSE-APACHE)
- [crates/foxguard/LICENSE-MIT](crates/foxguard/LICENSE-MIT) and [crates/foxguard/LICENSE-APACHE](crates/foxguard/LICENSE-APACHE) (the imported Foxguard engine, same MIT OR Apache-2.0 terms, original copyright notice kept)
- [enterprise/LICENSE](enterprise/LICENSE)

To get a key, see https://0.security/enterprise/.
