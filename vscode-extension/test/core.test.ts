import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { applyEdit, compareVersions, computeFix, dependencyUpgrade, fixKind, isVersion, reindent, stripFences } from "../src/core/fixes";
import { groupFindings, isFilterActive, matchesFilter, summarize, summaryText } from "../src/core/grouping";
import { shiftForChange } from "../src/core/lineTracking";
import { applyPackageJsonPatch, planUpgrade } from "../src/core/packageManagers";
import { findingKey, isPlaceholder, parseReport, track } from "../src/core/report";
import { EMPTY_FILTER, Finding } from "../src/core/types";

// Real output of `cli.py scan <sample app> --json --no-ai` (35 findings).
const fixture = parseReport(JSON.parse(readFileSync(join(__dirname, "..", "..", "test", "fixtures", "sample-results.json"), "utf8")));

function finding(over: Partial<Finding>): Finding {
  return parseReport({ vulnerabilities: [{ id: "vuln_001", title: "t", severity: "high", file: "a.py", line: 1, rule_id: "r", category: "code", ...over }] })
    .vulnerabilities[0];
}

// ----- report parsing -----

test("parseReport normalises the fixture", () => {
  assert.equal(fixture.vulnerabilities.length, 35);
  assert.deepEqual(fixture.languages, ["python"]);
  const sec = fixture.vulnerabilities.find((v) => v.category === "secret")!;
  assert.equal(sec.file, "app.py");
  assert.equal(sec.line, 7);
});

test("parseReport rejects wrong shapes and fixes bad fields", () => {
  assert.throws(() => parseReport({}));
  assert.throws(() => parseReport(null));
  const f = parseReport({ vulnerabilities: [{ severity: "BOGUS", category: "x", file: ".\\src\\a.py", line: -3 }] }).vulnerabilities[0];
  assert.equal(f.severity, "low");
  assert.equal(f.category, "code");
  assert.equal(f.file, "src/a.py");
  assert.equal(f.line, 1);
  assert.equal(f.end_line, 1);
});

test("findingKey is stable across scans and ignores positional ids and whitespace", () => {
  const a = finding({ id: "vuln_001", vulnerable_code: "x  =  1" });
  const b = finding({ id: "vuln_009", vulnerable_code: "x = 1", line: 40 });
  assert.equal(findingKey(a), findingKey(b));
  assert.notEqual(findingKey(a), findingKey(finding({ vulnerable_code: "x = 2" })));
});

test("isPlaceholder spots backend filler text", () => {
  assert.ok(isPlaceholder("(AI enhancement unavailable — set GROQ_API_KEY for detailed fixes)"));
  assert.ok(isPlaceholder("   "));
  assert.ok(!isPlaceholder("Use parameterised queries."));
});

// ----- grouping / filtering -----

test("group by severity: ordered, non-empty, counts add up", () => {
  const tracked = track(fixture.vulnerabilities, new Set());
  const groups = groupFindings(tracked, "severity", EMPTY_FILTER);
  assert.deepEqual(groups.map((g) => g.value), ["critical", "high", "medium", "low"]);
  assert.equal(groups.reduce((n, g) => n + g.findings.length, 0), 35);
  assert.equal(groups[0].findings.length, 1);
});

test("group by file: highest severity file first, findings sorted by line", () => {
  const groups = groupFindings(track(fixture.vulnerabilities, new Set()), "file", EMPTY_FILTER);
  assert.deepEqual(groups.map((g) => g.value), ["app.py", "requirements.txt"]);
  const lines = groups[0].findings.map((t) => t.line);
  assert.deepEqual(lines, [...lines].sort((a, b) => a - b));
});

test("group by category", () => {
  const groups = groupFindings(track(fixture.vulnerabilities, new Set()), "category", EMPTY_FILTER);
  assert.deepEqual(groups.map((g) => [g.value, g.findings.length]), [["code", 4], ["dependency", 30], ["secret", 1]]);
});

test("filters: severity, category, text and ignored", () => {
  const tracked = track(fixture.vulnerabilities, new Set());
  const only = (f: Partial<typeof EMPTY_FILTER>) => tracked.filter((t) => matchesFilter(t, { ...EMPTY_FILTER, ...f })).length;
  assert.equal(only({ severities: ["critical", "high"] }), 7);
  assert.equal(only({ categories: ["secret"] }), 1);
  assert.equal(only({ text: "JINJA2 sandbox" }), 6);
  assert.ok(isFilterActive({ ...EMPTY_FILTER, text: "x" }));
  assert.ok(!isFilterActive(EMPTY_FILTER));

  tracked[0].ignored = true;
  assert.equal(only({}), 34);
  assert.equal(only({ showIgnored: true }), 35);
  const s = summarize(tracked);
  assert.equal(s.total, 34);
  assert.equal(s.ignored, 1);
  assert.match(summaryText(s), /^34 findings · .* · 1 ignored$/);
});

test("ignored keys carry over into a new scan", () => {
  const key = findingKey(fixture.vulnerabilities[0]);
  const tracked = track(fixture.vulnerabilities, new Set([key]));
  assert.ok(tracked[0].ignored);
  assert.equal(tracked.filter((t) => t.ignored).length >= 1, true);
});

// ----- fixes -----

const appPy = [
  "def user():",
  "    name = request.args.get('name')",
  "    cur.execute(\"SELECT * FROM users WHERE name = '\" + name + \"'\")",
  "    return str(cur.fetchall())",
];

test("code fix: replaces the matched lines and re-indents the AI snippet", () => {
  const f = finding({
    line: 3,
    end_line: 3,
    vulnerable_code: "    cur.execute(\"SELECT * FROM users WHERE name = '\" + name + \"'\")",
    fixed_code: "```python\ncur.execute(\"SELECT * FROM users WHERE name = ?\", (name,))\n```",
  });
  assert.equal(fixKind(f), "code");
  const r = computeFix(f, appPy);
  assert.ok(r.ok);
  if (!r.ok) return;
  assert.deepEqual(r.edit, { startLine: 2, endLine: 2, lines: ['    cur.execute("SELECT * FROM users WHERE name = ?", (name,))'] });
  assert.equal(applyEdit(appPy, r.edit).length, 4);
});

test("code fix: finds a multi-line snippet with context even if the file shifted", () => {
  const shifted = ["import os", "", ...appPy];
  const f = finding({ line: 3, vulnerable_code: appPy.slice(1, 4).join("\n"), fixed_code: "a = 1\nif a:\n    b = 2" });
  const r = computeFix(f, shifted);
  assert.ok(r.ok);
  if (!r.ok) return;
  assert.equal(r.edit.startLine, 3);
  assert.equal(r.edit.endLine, 5);
  assert.deepEqual(r.edit.lines, ["    a = 1", "    if a:", "        b = 2"]);
});

test("code fix: refuses when the code changed", () => {
  const f = finding({ vulnerable_code: "eval(x)", fixed_code: "ast.literal_eval(x)" });
  const r = computeFix(f, appPy);
  assert.equal(r.ok, false);
});

test("no fix for placeholders, secrets, or identical code", () => {
  const sev = fixture.vulnerabilities;
  assert.equal(fixKind(sev.find((v) => v.category === "code")!), null); // --no-ai placeholder
  assert.equal(fixKind(sev.find((v) => v.category === "secret")!), null);
  assert.equal(fixKind(finding({ vulnerable_code: "x = 1", fixed_code: "x = 1" })), null);
});

test("dependency fix: bumps the version on the manifest line", () => {
  const dep = fixture.vulnerabilities.find((v) => v.category === "dependency" && v.package === "flask" && v.fixed_version)!;
  const doc = ["Flask==0.12.2", "requests==2.19.0"];
  assert.equal(fixKind(dep), "dependency");
  const r = computeFix(dep, doc);
  assert.ok(r.ok);
  if (!r.ok) return;
  assert.deepEqual(r.edit, { startLine: 0, endLine: 0, lines: [`Flask==${dep.fixed_version}`] });
});

test("dependency fix: package.json style line, searched near the reported line", () => {
  const f = finding({ category: "dependency", package: "lodash", installed_version: "4.17.15", fixed_version: "4.17.21", line: 1 });
  const doc = ["{", '  "dependencies": {', '    "lodash": "^4.17.15"', "  }", "}"];
  const r = computeFix(f, doc);
  assert.ok(r.ok);
  if (!r.ok) return;
  assert.deepEqual(r.edit.lines, ['    "lodash": "^4.17.21"']);
});

test("version helpers: real versions only, numeric ordering", () => {
  assert.ok(isVersion("2.32.4"));
  assert.ok(isVersion("1.0"));
  assert.ok(isVersion("3.0.0-rc1"));
  assert.ok(!isVersion("c45d7c49ea75133e52ab22a8e9e13173938e36ff"));
  assert.ok(!isVersion(""));
  assert.ok(compareVersions("2.10.1", "2.9") > 0);
  assert.ok(compareVersions("3.1.3", "3.1.6") < 0);
  assert.equal(compareVersions("1.0", "1.0.0"), 0);
});

test("dependency upgrade: one click fixes every advisory with a published version", () => {
  const all = fixture.vulnerabilities;
  const first = all.find((v) => v.package === "requests" && v.fixed_version === "2.20.0")!;
  const up = dependencyUpgrade(first, all)!;
  assert.equal(up.target, "2.33.0");
  assert.equal(up.siblings.length, 10);
  assert.equal(up.covered.length, 8); // the other 2 only list git commits as their fix
  const r = computeFix(first, ["flask==0.12.2", "requests==2.19.0"], first.line, up.target);
  assert.ok(r.ok);
  if (r.ok) assert.deepEqual(r.edit.lines, ["requests==2.33.0"]);
  // a commit hash is never offered as a fix
  const hashOnly = all.find((v) => v.package === "requests" && !isVersion(v.fixed_version))!;
  assert.equal(fixKind(hashOnly), null);
});

test("stripFences and reindent helpers", () => {
  assert.equal(stripFences("```js\nfoo()\n```"), "foo()");
  assert.equal(stripFences("foo()"), "foo()");
  assert.deepEqual(reindent(["  a", "    b", ""], ["\tx"]), ["\ta", "\t  b", ""]);
});

// ----- line tracking -----

test("line tracking: edits above shift, edits on the lines overlap, edits below do nothing", () => {
  // finding on lines 10-11 (1-based)
  assert.deepEqual(shiftForChange(10, 11, { startLine: 2, endLine: 2, endCharacter: 5, insertedLineBreaks: 2 }), { kind: "shifted", line: 12, endLine: 13 });
  assert.deepEqual(shiftForChange(10, 11, { startLine: 2, endLine: 4, endCharacter: 0, insertedLineBreaks: 0 }), { kind: "shifted", line: 8, endLine: 9 });
  // Enter pressed at column 0 of the finding's first line pushes it down
  assert.deepEqual(shiftForChange(10, 11, { startLine: 9, endLine: 9, endCharacter: 0, insertedLineBreaks: 1 }), { kind: "shifted", line: 11, endLine: 12 });
  assert.deepEqual(shiftForChange(10, 11, { startLine: 9, endLine: 9, endCharacter: 4, insertedLineBreaks: 0 }), { kind: "overlap" });
  assert.deepEqual(shiftForChange(10, 11, { startLine: 20, endLine: 20, endCharacter: 0, insertedLineBreaks: 3 }), { kind: "unchanged" });
  assert.deepEqual(shiftForChange(10, 11, { startLine: 3, endLine: 3, endCharacter: 9, insertedLineBreaks: 0 }), { kind: "unchanged" });
});

// ----- package managers -----

test("planUpgrade: npm direct dependency runs npm install with the right save flag", () => {
  const pj = { dependencies: { lodash: "4.17.15" }, devDependencies: { minimist: "1.2.0" } };
  const direct = planUpgrade("web/package-lock.json", "lodash", "4.17.21", pj);
  assert.equal(direct.kind, "run");
  if (direct.kind === "run") {
    assert.deepEqual(direct.argv, ["install", "lodash@^4.17.21", "--save", "--no-audit", "--no-fund"]);
    assert.equal(direct.patch, undefined);
  }
  const dev = planUpgrade("package-lock.json", "minimist", "1.2.6", pj);
  assert.ok(dev.kind === "run" && dev.argv.includes("--save-dev"));
});

test("planUpgrade: npm transitive dependency adds an override", () => {
  const p = planUpgrade("package-lock.json", "qs", "6.14.1", { dependencies: { express: "4.17.1" } });
  assert.ok(p.kind === "run");
  if (p.kind === "run") {
    assert.equal(p.direct, false);
    assert.deepEqual(p.patch, { field: "overrides", name: "qs", range: "^6.14.1" });
    assert.deepEqual(p.argv, ["install", "--no-audit", "--no-fund"]);
  }
});

test("planUpgrade: yarn, other ecosystems and plain manifests", () => {
  const y = planUpgrade("yarn.lock", "lodash", "4.17.21", { devDependencies: { lodash: "^4.0.0" } });
  assert.ok(y.kind === "run" && y.tool === "yarn" && y.argv.join(" ") === "add lodash@^4.17.21 --dev");
  const yt = planUpgrade("yarn.lock", "qs", "6.14.1", {});
  assert.ok(yt.kind === "run" && yt.patch?.field === "resolutions");
  assert.equal(planUpgrade("requirements.txt", "flask", "3.1.3", null).kind, "edit");
  assert.equal(planUpgrade("api/requirements-dev.txt", "flask", "3.1.3", null).kind, "edit");
  const poetry = planUpgrade("poetry.lock", "jinja2", "3.1.6", null);
  assert.ok(poetry.kind === "manual" && poetry.command === 'poetry add "jinja2>=3.1.6"');
  const go = planUpgrade("go.mod", "golang.org/x/net", "0.23.0", null);
  assert.ok(go.kind === "manual" && go.command === "go get golang.org/x/net@v0.23.0");
  assert.equal(planUpgrade("package-lock.json", "qs", "6.14.1", null).kind, "manual");
});

test("applyPackageJsonPatch keeps indentation and existing overrides", () => {
  const text = '{\r\n    "name": "x",\r\n    "overrides": {\r\n        "a": "1.0.0"\r\n    }\r\n}\r\n';
  const out = applyPackageJsonPatch(text, { field: "overrides", name: "qs", range: "^6.14.1" });
  assert.deepEqual(JSON.parse(out).overrides, { a: "1.0.0", qs: "^6.14.1" });
  assert.ok(out.includes('\r\n    "name"'));
  assert.ok(out.endsWith("}\r\n"));
});
