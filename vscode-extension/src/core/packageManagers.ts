// How to upgrade a vulnerable package, depending on the manifest the scanner found it in.
// Lockfiles must never be edited by hand (integrity hashes, resolved URLs, the dependency tree),
// so for them we run the package manager instead.

export interface PackageJson {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  overrides?: Record<string, unknown>;
  resolutions?: Record<string, unknown>;
}

export type DependencySection = "dependencies" | "devDependencies" | "optionalDependencies" | "peerDependencies";

/** Force a version of a package that is only pulled in by other packages (npm overrides / yarn resolutions). */
export interface PackageJsonPatch {
  field: "overrides" | "resolutions";
  name: string;
  range: string;
}

export type UpgradePlan =
  /** Plain manifest with pinned versions (requirements.txt): edit the line directly. */
  | { kind: "edit" }
  /** Run the package manager; it updates the manifest, the lockfile and installed packages together. */
  | {
      kind: "run";
      tool: string;
      argv: string[];
      /** Package is listed in package.json (false = transitive, forced via `patch`). */
      direct: boolean;
      patch?: PackageJsonPatch;
      summary: string;
    }
  /** Ecosystems we don't drive automatically: the command is typed into a terminal for the user to run. */
  | { kind: "manual"; tool: string; command: string; summary: string };

const basename = (p: string) => p.replace(/\\/g, "/").split("/").pop()!.toLowerCase();

export function directSection(pkg: PackageJson | null, name: string): DependencySection | null {
  if (!pkg) return null;
  for (const s of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"] as const) {
    if (pkg[s] && Object.prototype.hasOwnProperty.call(pkg[s], name)) return s;
  }
  return null;
}

const NPM_SAVE_FLAG: Record<DependencySection, string> = {
  dependencies: "--save",
  devDependencies: "--save-dev",
  optionalDependencies: "--save-optional",
  peerDependencies: "--save-peer",
};

/**
 * Works out how to upgrade `name` to `target` given the manifest file the finding points at
 * (repo-relative or absolute) and, for npm/yarn, the package.json next to it.
 */
export function planUpgrade(manifest: string, name: string, target: string, packageJson: PackageJson | null): UpgradePlan {
  const file = basename(manifest);
  const range = `^${target}`;

  if (file === "package-lock.json" || file === "npm-shrinkwrap.json") {
    if (!packageJson) return { kind: "manual", tool: "npm", command: `npm install ${name}@${range}`, summary: `No package.json next to ${file}.` };
    const section = directSection(packageJson, name);
    if (section) {
      return {
        kind: "run",
        tool: "npm",
        argv: ["install", `${name}@${range}`, NPM_SAVE_FLAG[section], "--no-audit", "--no-fund"],
        direct: true,
        summary: `npm install ${name}@${range} (updates package.json, package-lock.json and node_modules)`,
      };
    }
    return {
      kind: "run",
      tool: "npm",
      argv: ["install", "--no-audit", "--no-fund"],
      direct: false,
      patch: { field: "overrides", name, range },
      summary: `${name} is not in package.json (another package pulls it in). Adds "overrides": { "${name}": "${range}" } to package.json, then runs npm install.`,
    };
  }

  if (file === "yarn.lock") {
    if (!packageJson) return { kind: "manual", tool: "yarn", command: `yarn add ${name}@${range}`, summary: `No package.json next to ${file}.` };
    const section = directSection(packageJson, name);
    if (section) {
      const flag = section === "devDependencies" ? ["--dev"] : section === "optionalDependencies" ? ["--optional"] : section === "peerDependencies" ? ["--peer"] : [];
      return {
        kind: "run",
        tool: "yarn",
        argv: ["add", `${name}@${range}`, ...flag],
        direct: true,
        summary: `yarn add ${name}@${range} (updates package.json, yarn.lock and node_modules)`,
      };
    }
    return {
      kind: "run",
      tool: "yarn",
      argv: ["install"],
      direct: false,
      patch: { field: "resolutions", name, range },
      summary: `${name} is not in package.json (another package pulls it in). Adds "resolutions": { "${name}": "${range}" } to package.json, then runs yarn install.`,
    };
  }

  const manual = (tool: string, command: string): UpgradePlan => ({ kind: "manual", tool, command, summary: `Run \`${command}\` to update ${file}.` });
  if (file === "pipfile.lock") return manual("pipenv", `pipenv install "${name}>=${target}"`);
  if (file === "poetry.lock") return manual("poetry", `poetry add "${name}>=${target}"`);
  if (file === "composer.lock") return manual("composer", `composer require "${name}:^${target.replace(/^v/, "")}"`);
  if (file === "gemfile.lock") return manual("bundler", `bundle update ${name}`);
  if (file === "go.mod") {
    // One command: `&&` is not valid in Windows PowerShell 5.
    const command = `go get ${name}@v${target.replace(/^v/, "")}`;
    return { kind: "manual", tool: "go", command, summary: `Run \`${command}\`, then \`go mod tidy\`, to update go.mod and go.sum.` };
  }

  return { kind: "edit" }; // requirements*.txt and other pinned plain-text manifests
}

/** package.json text with the override/resolution set, keeping the file's indentation and EOL. */
export function applyPackageJsonPatch(text: string, patch: PackageJsonPatch): string {
  const data = JSON.parse(text) as Record<string, unknown>;
  const field = (data[patch.field] && typeof data[patch.field] === "object" ? data[patch.field] : {}) as Record<string, unknown>;
  field[patch.name] = patch.range;
  data[patch.field] = field;
  const indent = text.match(/^[ \t]+(?=")/m)?.[0] ?? "  ";
  const eol = text.includes("\r\n") ? "\r\n" : "\n";
  return JSON.stringify(data, null, indent).replace(/\n/g, eol) + eol;
}
