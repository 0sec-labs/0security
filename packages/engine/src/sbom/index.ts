export { LOCKFILES, parseCargoLock, parseComposerLock, parseGemfileLock, parseGoMod, parseGradleLock, parseMixLock, parseNugetLock, parsePubspecLock, parseNpmLock, parsePipfileLock, parsePnpmLock, parsePoetryLock, parseRequirements, parseYarnLock, sriToHashes, type Component, type Hash } from "./parsers.js";
export { classifyLicense, generateSbom, packageUrl, type Bom, type LibraryComponent, type LicenseChoice, type SbomResult } from "./cyclonedx.js";
export { checkBomAgainstOsv, type Advisory, type OsvOptions } from "./osv.js";
export { toSpdx, type SpdxDocument, type SpdxPackage } from "./spdx.js";
export { DEFAULT_GENERATOR_TIMEOUT_MS, EXTERNAL_GENERATORS, GeneratorFailedError, GeneratorNotInstalledError, runExternalGenerator, type ExternalGenerator } from "./external.js";
export { detectAi, type AiComponent, type AiService } from "./ai.js";
