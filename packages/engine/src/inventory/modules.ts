/**
 * The build modules of a Java code base, found from the folder layout alone.
 *
 * A module is a directory that holds a Maven `pom.xml` or a Gradle `build.gradle`, `build.gradle.kts` or `settings.gradle`
 * file. A file belongs to the module of its nearest such ancestor directory. Only the file names are checked: the build files
 * are not read, so a repository cannot steer the plan through their content. Used to keep a batch inside one module.
 */
import { existsSync } from "node:fs";
import { join } from "node:path";

export type ModuleKind = "maven" | "gradle";
export interface BuildModule {
  /** Relative to the folder, forward slashes; "." for the folder itself. */
  root: string;
  kind: ModuleKind;
}

const MARKERS: ReadonlyArray<{ file: string; kind: ModuleKind }> = [
  { file: "pom.xml", kind: "maven" },
  { file: "build.gradle", kind: "gradle" },
  { file: "build.gradle.kts", kind: "gradle" },
  { file: "settings.gradle", kind: "gradle" },
  { file: "settings.gradle.kts", kind: "gradle" },
];

/** The directory part of a relative path ("." for a top-level file). */
const dirOf = (path: string): string => (path.includes("/") ? path.slice(0, path.lastIndexOf("/")) : ".");

/**
 * Returns a function from a relative file or directory path to the module that holds it, or undefined when no ancestor has a
 * build file. `isDir` says the path is a directory (an `other` unit's path); otherwise its parent directory is used.
 */
export function javaModuleResolver(folder: string, exists: (path: string) => boolean = existsSync): (path: string, isDir?: boolean) => BuildModule | undefined {
  const cache = new Map<string, BuildModule | null>();
  const resolveDir = (dir: string): BuildModule | undefined => {
    const hit = cache.get(dir);
    if (hit !== undefined) return hit ?? undefined;
    const marker = MARKERS.find(item => exists(dir === "." ? join(folder, item.file) : join(folder, dir, item.file)));
    const found: BuildModule | undefined = marker ? { root: dir, kind: marker.kind } : dir === "." ? undefined : resolveDir(dirOf(dir));
    cache.set(dir, found ?? null);
    return found;
  };
  return (path, isDir = false) => resolveDir(isDir ? path || "." : dirOf(path));
}

/** The Java package of a source path under `src/main/java` or `src/test/java`, like `org.example.web`; undefined elsewhere. */
export function javaPackageOf(path: string): string | undefined {
  const match = /(?:^|\/)src\/(?:main|test)\/java\/(.+)$/.exec(path);
  if (!match) return undefined;
  const dir = dirOf(match[1]!);
  return dir === "." ? "(default package)" : dir.replace(/\//g, ".");
}
