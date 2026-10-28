# Chain-of-weakness analysis and post-fix validation

The scanner does not stop at isolated findings. It works out how weaknesses connect
into an exploitable outcome, suggests a fix at the point where the chain can be
interrupted reliably, and then checks, with evidence, whether a fix actually removes
the risk. One workflow:

```
detect (Semgrep, OSV, secrets) ─▶ data-flow analysis ─▶ chains ─▶ chain-aware fix
                                                                       │
          ┌──────────── failure evidence (open paths, regressions) ◀───┤
          ▼                                                            ▼
     next suggestion ◀── FAIL / NEW_VULNERABILITY ◀── validate in a sandbox copy ─▶ PASS / INCONCLUSIVE
```

## How it fits the existing system

| Step | Where | What changed |
|---|---|---|
| Detection | `semgrep_runner`, `dependency_scanner`, `secret_scanner` | Unchanged. `run_scan` gained an optional `targets` list for re-checks. |
| Data flow | `services/flow_analyzer.py` (new) | Python `ast` analysis: sources, propagation, sanitizers and validation guards, sinks, auth checks, same-module calls. |
| Chains | `services/chain_analysis.py` (new) | New pipeline step `chain_analysis` (between secret scan and AI). Links findings to chains only with evidence. |
| Fix suggestion | `services/fix_planner.py` (new), `ai_enhancer.py` | Chain-level fix (break point + edits). Per-finding AI prompts now get their chain as context. |
| Validation | `services/fix_validation.py` (new), `routers/chains.py` (new) | Sandbox loop with bounded retries, exposed through the API. |
| Isolation | `utils/sandbox.py` (new) | Restricted environment, path containment, tree hashing. |
| UI | `components/AttackChains.tsx`, `components/ChainFixPanel.tsx` (new) | Chain section on the results page; findings link to their chains. |
| CLI | `cli.py` | Scan output and `--json` include chains; new `validate` command. |

Semgrep's community edition reports *where* a rule matched but no source-to-sink
trace (checked with `--dataflow-traces` in both SARIF and JSON output), so the
relationships come from our own analysis, and Semgrep findings are attached as
corroborating evidence.

## The chain model

A chain is built around one **sensitive operation** (a sink) and contains every path into it.

| Node kind | Example | Role |
|---|---|---|
| `entry_point` | `POST /login` | context |
| `condition` | No authentication on `POST /login` | contributing |
| `security_control` | `login_required`, `re.fullmatch` check, `int()` | control (blocks) or contributing (weak) |
| `weakness` | No validation of `username`; hardcoded session key; vulnerable dependency | contributing |
| `untrusted_input` | `request.form.get('username')` | context |
| `sensitive_operation` | `cursor.execute` with a query built from input | direct |
| `impact` | SQL injection | impact |

Each **edge** has a relation (`attacker-controlled value reaches`, `allows forging the
session checked by`, …), a status (`confirmed` or `hypothesis`), a confidence, and
**evidence**, each tagged with its kind so you can tell how a claim was established:

| Evidence kind | Meaning |
|---|---|
| `static_dataflow` | Path step found by `flow_analyzer` |
| `scanner_finding` | A detector flagged this line |
| `code_pattern` | Structural fact (decorator, literal assignment) |
| `inferred` | Follows from framework semantics, not observed |
| `test_observation` | Observed while validating a fix |
| `manual` | Confirmed by a person (reserved) |

Chains support any length, several inputs converging on one sink, and one sink
reached from several routes (via a shared helper).

### What gets linked, and what does not

- **Input → operation** needs a data-flow path. Two findings in the same file are not related because of that.
- A **scanner finding** is attached only if it is on a line of the path and its rule matches the operation's class (an XSS rule is never attached to a SQL chain).
- A **hardcoded secret key** is linked only to routes whose authentication relies on the signed session cookie (`session`/`current_user`/`login_required`), not to JWT- or token-protected routes.
- A **vulnerable dependency** is linked only when the operation calls into that package, and the edge is always a `hypothesis` (the advisory may not affect that function).
- Propagation through an unknown function is *assumed* and makes the edge a `hypothesis`.

### Prioritisation

`priority = impact (0-10) × exploitability factor × evidence confidence`, where
exploitability is:

- **likely**: confirmed path, no effective validation, network input, no authentication (or authentication bypassable with the hardcoded key)
- **possible**: authentication required, weak or unverified validation, an assumed step, local input, or unknown entry point
- **mitigated**: every path passes a control that neutralises this class (e.g. an allowlist regex, `int()`, `shlex.quote` for shell commands)

"likely" still means *statically reachable*; nothing is executed. The text in
`exploitability_reason` and `uncertainty` says exactly what was and was not established.

## Chain-aware fixes

The default break point is the **sensitive operation**: making it safe for any input
(parameterized query, argument list without a shell, `json.loads` instead of `pickle`,
autoescaped template, `secure_filename` on the user part of a path) covers every path
into it. Each fix lists:

- `target_nodes`: the weaknesses it addresses
- `remaining_paths`: other paths to the same outcome it does **not** cover (e.g. a second query in the same route)
- `tests`: the checks validation will run

Fix sources, in order of use:

1. **Template**: small AST-based rewrites for recognised code shapes. They decline anything they cannot rewrite safely (a query passed in as a variable, `LIKE '%…%'`, a value inside a longer string literal, shell metacharacters) instead of guessing.
2. **Retry extension**: keeps the previous attempt and applies the template to the paths the validator reported still open.
3. **AI (Groq)**: given the chain, its evidence, the code with line numbers, and every earlier attempt with its failure evidence. Edits are only accepted inside files of the chain.
4. **Developer**: edits you submit (also editable in the UI before validating).

## Post-fix validation

Every finding can be validated, not only attack chains (`services/finding_validation.py`):

| Finding | First fix | Re-check after each attempt |
|---|---|---|
| Code, any language | The scan's AI-suggested code, placed on the flagged lines | Semgrep on the file before vs after: the rule must stop matching where it did; no new findings; syntax (Python, JavaScript via `node --check`, JSON, PHP / Ruby when installed); Python regressions |
| Dependency | Pin the advisory's fixed version (`requirements*.txt`, `go.mod`) | OSV.dev for the new version; new advisories make the next attempt upgrade further |
| Secret | Read the value from an environment variable (Python / JavaScript assignments) | Secret scanner, and the value must be gone from the file. Diffs shown in the UI are masked. |

A finding on a Python attack chain uses the chain checks below instead. Later
attempts come from the LLM, given the current code and the failure evidence.

**The code carries forward.** Attempt 1 applies its fix to a copy of the scanned
code. If an attempt improves on the best so far (and still parses), the next
attempt is applied **on top of that code**, so each revision only adds what is
still missing. The last kept attempt holds the final code. The result's
`final_fix` (edits against the original) and `final_diff` describe that final
code, and a passing final fix replaces the original suggestion in the results.
Every attempt is still checked against the original scanned code, so nothing an
earlier attempt changed escapes the checks.

For a chain, each attempt collects this evidence:

| Check | Fails when |
|---|---|
| `apply_patch` | The edit does not match the scanned code (stale patch) or escapes the workspace |
| `syntax` | A changed Python file no longer parses |
| `reproduce_original` | An unblocked path still reaches the chain's operation |
| `alternative_paths` | Another unblocked path of the same class starts at the same route or input |
| `regression_static` | A route or function was removed, a name is used but not defined, or an import no longer exists in current library versions (e.g. `flask.escape`) |
| `scanner_recheck` | Semgrep (changed + chain files, before vs after) still matches the linked rule |
| `project_tests` | Opt-in project test command passes before the fix but fails after it |

Three separate verdicts are reported, because they are not the same thing:

- **weakness addressed**: the targeted operation no longer receives untrusted data
- **path broken**: none of the original paths is still open
- **risk eliminated**: both of the above, and no alternative path to the same outcome

### Outcomes

| Status | When |
|---|---|
| `PASS` | Not reproducible under these checks, no alternative path, no blocking regression, no new issue. Reported as *validated within the scope of the performed checks*, never as proof of security. |
| `FAIL` | Original or alternative path still open, or a blocking regression. The failing check, path and evidence feed the next suggestion. |
| `NEW_VULNERABILITY` | The original chain is broken but the change adds a path or finding, classified as `extends_chain`, `new_chain` or `unrelated`. |
| `INCONCLUSIVE` | The patch did not apply, a required check could not run (e.g. Semgrep unavailable while the chain has scanner evidence), the chain has no open path to reproduce, no fix could be produced, or the evidence conflicts (data flow says fixed, the linked scanner rule still fires). Manual review is requested. |

A compile or test run passing never yields `PASS` on its own: `reproduce_original`
and `alternative_paths` must run and come back clean.

### Attempts, early stopping and statistics

- **Limit:** `FIX_MAX_ATTEMPTS` sets the total attempts per validation: default 3, hard cap 5. It can also be set per request with `max_attempts`.
- **Evidence-driven revisions:** every revision is built from the latest failure evidence (the paths still open, regressions, new issues). A fix identical to an earlier attempt is never validated twice.
- **Progress score:** each attempt gets one (lower is better, 0 means every check is clean). It is a weighted count of still-open paths (×10), alternative paths, regressions and new issues (×5 each), and a lingering scanner match (×2). A syntax error scores 100.
- **Early stopping:** the loop ends at the first of these:
  - PASS
  - INCONCLUSIVE
  - no new fix can be derived (`no_fix`)
  - an attempt that does not beat the best score so far (`stalled`)
  - the attempt limit (`limit`)
- **Results kept:** the outcome is stored as `stop_reason` and `best_attempt`. `final_fix` is the passing fix, or else the best revision. A passing fix becomes the chain's fix in the scan results, so the UI shows the verified code instead of the first suggestion.
- **Statistics:** `GET /api/validation-stats` reports, across all finished validations:
  - how many reached each attempt and passed there
  - the cumulative pass rate
  - the stop reasons
  - how many hit the limit while still improving
  - one line of advice

  The advice applies these rules:
  - Most passes on attempt 1 or 2 means raising the limit is unlikely to help.
  - 30% or more of validations hitting the limit while still improving means a higher limit (max 5) may help.
  - With fewer than 5 finished validations, there is not enough data to judge.

### Persistent attempt history (MongoDB)

Every attempt is stored in MongoDB as it runs (`services/validation_history.py`). The store is configured with `MONGODB_URI` / `MONGODB_DATABASE` (see docs/SETUP.md). There is no fallback store: without MongoDB, Validate Fix answers 503 with setup instructions, and scanning still works.

**Investigations**

An investigation is the effort to fix one problem: a chain, or a finding of one scan.

- **Resume:** clicking Validate Fix again resumes the current investigation.
  - Numbering continues (attempts 4, 5, …).
  - The run starts from the best code so far (`best_fix`, kept on the investigation).
  - Every earlier attempt is the fix generator's history.
- **Limit:** `INVESTIGATION_MAX_ATTEMPTS` (default 10) counts attempts across all runs; each run still uses at most `FIX_MAX_ATTEMPTS`.
- **No silent fresh start:** once an investigation has `passed` or is `exhausted`, further clicks are refused with 409 (`investigation_passed` / `investigation_exhausted`). Only an explicit request (`new_investigation: true`, the UI's "Start a new investigation") closes it and opens another.

**Attempt lifecycle**

1. The attempt is created as `RUNNING` **before** its fix is generated, with:
   - its id, the investigation id and the run (`validation_id`)
   - its `attempt_number` (unique per investigation) and the `parent_attempt_id` of the attempt before it, within a run and across clicks
2. Then, as it progresses:
   - `phase: generating` → the fix: strategy, `strategy_id`, the history note, the patch
   - `phase: applying` → the one `code_hash`
   - `phase: validating` → checks, outcome, `failure_reason`, diff, status, timestamps

The attempt also records the finding, the rule and the vulnerability class.

**Statuses**

- `PASSED`
- `FAILED`: includes a fix that adds a new vulnerability.
- `INCONCLUSIVE`: the evidence does not decide (a stale patch, or conflicting evidence), or no fix could be generated.
- `ERROR`: a scanner, OSV.dev or the test runner could not run, or the backend crashed during setup, generation or validation. The phase it reached is recorded. ERROR says nothing about the fix.
- `SKIPPED`: the fix produced exactly the code an earlier attempt of the investigation already validated. It is recorded with its hash and that attempt, and not validated again.

**Code hash**

One SHA-256 per attempt, over the sorted relative paths and contents of the validated snapshot. `.git`, `node_modules` and virtualenvs are skipped. The same code gives the same hash in any location; when the patch did not apply, it is the unpatched code.

**Integrity**

- **Append-only:** documents are only updated while `RUNNING`, every write filters on that, and the code never deletes them. Unlike the earlier SQLite triggers, MongoDB cannot enforce this for other clients.
- **Indexes:**
  - unique `(investigation_id, attempt_number)`: also rejects racing writers
  - unique partial index on the investigation's `current_key`: one current investigation per problem
  - indexes for the history and strategy queries
- **One run per investigation:** a run claims the investigation atomically. Attempt numbers are allocated per investigation, never from a global counter.
- **Crashes and restarts:**
  - A crash marks the run's `RUNNING` attempts `ERROR`; a run that fails before its first attempt (e.g. the clone) still records one `ERROR` attempt.
  - The first MongoDB connection of a new backend process marks attempts left `RUNNING` as `ERROR` and releases stale claims. This assumes one backend process per database.

**How history influences the next attempt**

1. **Same investigation:**
   - Earlier attempts are the generator's history: template retries target what is still open, and the LLM sees the earlier patches and failure reasons.
   - The run resumes from the best code.
   - Identical code is `SKIPPED`.
2. **Rule-based strategy order** (`fix_planner.choose`, shared by the chain and single-finding paths). Each predefined strategy has a `strategy_id`: `template:<kind>`, `template:secret-env`, `template:dependency-upgrade` or `scan-suggestion`.
   - Its record (passed / failed) is taken from evaluated attempts on the same rule or vulnerability class in other investigations, plus this investigation's own attempts. ERROR, SKIPPED and patches that did not apply don't count.
   - If it failed at least `HISTORY_AVOID_AFTER_FAILURES` times (default 2) and never passed, it is tried **after** the LLM instead of first.
   - It is never dropped: without an LLM, or when the LLM has no usable fix, it is still used as the fallback, so the rule-based behavior remains the baseline.
   - The choice is recorded on the attempt (`strategy_id`, `selection_note`) and shown in the UI. With a single candidate (e.g. dependency upgrades), history changes nothing and no note is written.
   - Free-form LLM fixes and developer fixes are not ranked.
3. **LLM context:** the prompt gets each strategy's record and similar attempts elsewhere (most relevant first: same repo and file, same rule, same class; passes first). It asks the LLM to adapt, not copy, and to avoid approaches that failed.

Every generated fix, from history-informed choices included, goes through the same validation checks. Nothing reuses an earlier patch directly. This is retrieval and re-ordering, not model training. No accuracy improvement has been measured; the tests show *that* history changes the choice, not that it improves outcomes.

**API:** `GET /api/scan/{scan_id}/investigations/{investigation_id}` returns every attempt. A validation response carries `investigation_id`, `first_attempt` and `result`.

The UI shows each run's attempts and the full attempt history, with statuses, strategy, code hash, failure reasons, history notes, and the patch and check results (collapsed).

## Safety and isolation

- The original checkout is hashed before and after each attempt (`original_preserved`); fixes are applied only to `TEMP_DIR/validation-<id>/attempt-N`, deleted afterwards (keep with `VALIDATION_KEEP_WORKSPACE=1`).
- Edit paths are resolved inside the workspace; absolute paths and `..` escapes are refused.
- Subprocesses get a minimal environment without API keys or tokens.
- The scanned project's code is **not executed** unless you set `VALIDATION_TEST_COMMAND`. When set, it runs with this host's user privileges and network access, so only enable it for trusted code or inside a container.
- Nothing is committed, pushed or deployed. The validated diff is shown for a developer to review and apply.

## Running it

**Web app**: scan a repository, open a chain under "Attack chains", review the
suggested fix (or click "Edit before validating"), then "Validate fix in sandbox".

**API**

```bash
# validate the suggested fix
curl -X POST localhost:8000/api/scan/<scan_id>/chains/<chain_id>/validate -H "Content-Type: application/json" -d "{}"
# validate your own fix (original text is filled in and checked if omitted)
curl -X POST localhost:8000/api/scan/<scan_id>/chains/<chain_id>/validate -H "Content-Type: application/json" \
  -d '{"edits":[{"file":"app.py","start_line":45,"end_line":45,"replacement":"    cursor.execute(query, (username,))"}],"max_attempts":3}'
# poll
curl localhost:8000/api/scan/<scan_id>/validations/<validation_id>
```

Chains and validations are included in `GET /api/scan/{id}/results`.

**CLI** (local code, no GitHub needed)

```bash
cd backend
python cli.py scan ../my-app --json report.json     # chains are printed and in the JSON
python cli.py validate ../my-app-before ../my-app   # per chain: PASS / FAIL / ...; exit 1 unless all pass
python cli.py validate ../before ../after --chain chain_d693fe00e2 --no-semgrep
```

**Tests**

```bash
cd backend
pip install -r requirements-dev.txt
python -m pytest
```

The tests use fixture apps in `backend/tests/fixtures/` and a deterministic fake
scanner instead of Semgrep and Groq. They cover connected weaknesses, correct and
refused relationships, a fix that breaks the chain, a fix that leaves an alternative
path, regressions (undefined name, removed route, syntax error, removed import), new
vulnerabilities (extending a chain and a new chain), inconclusive cases, retries using
failure evidence, the retry limit, never repeating a suggestion, original-code
preservation, sandbox escapes, and BOM-encoded files.

Note: with `uvicorn --reload`, running the tests writes `__pycache__` under `backend/`
and restarts the dev server, which cancels scans in progress.

## Limitations

These are known and reported in the results rather than hidden:

- **Python only.** Other languages' findings are shown individually, with a coverage note. JavaScript would need a JS parser (e.g. via Node) to get the same evidence.
- **Calls are followed within a module only** (depth 3). A helper imported from another module ends the path; class methods are followed through `self`.
- **No dynamic confirmation.** Exploitability is static reachability; no request is sent to a running app. Runtime security tests would need the app running in a container.
- **Stored data is not tracked.** Data read back from a database (stored XSS, second-order SQL injection) is not treated as attacker-controlled.
- **Validation strength is graded by pattern**: allowlists, anchored regexes and `isdigit()` count as strong; blocklists, prefix checks and project-specific `is_valid()` functions are weak or unverified and never block a path.
- **Loops are evaluated once and containers are tainted as a whole**, which can over-report (e.g. a tainted list element) but not under-report within a function.
- **Scanner pattern rules** (e.g. "route returns a formatted string") may keep firing after a correct escape; this is reported as conflicting evidence (`INCONCLUSIVE`), not as a pass.
- **Regression checks are static** unless `VALIDATION_TEST_COMMAND` is set; behaviour changes (e.g. a pickle endpoint now expecting JSON) are explained in the fix rationale but not tested.
