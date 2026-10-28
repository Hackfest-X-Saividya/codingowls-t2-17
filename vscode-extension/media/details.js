// Finding Details webview. All scan data comes from scanned repositories, so it is only ever
// inserted with textContent / DOM APIs, never innerHTML.
(function () {
  const vscode = acquireVsCodeApi();
  const root = document.getElementById("root");

  function el(tag, attrs, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === "class") node.className = v;
      else if (k === "onclick") node.addEventListener("click", v);
      else node.setAttribute(k, v);
    }
    for (const c of children) {
      if (c === null || c === undefined || c === false) continue;
      node.append(typeof c === "string" ? document.createTextNode(c) : c);
    }
    return node;
  }

  const send = (command, uid) => vscode.postMessage({ type: "command", command, uid });

  function button(label, command, uid, primary, title) {
    return el("button", { class: primary ? "primary" : "secondary", title: title || label, onclick: () => send(command, uid) }, label);
  }

  function section(title, body, cls) {
    if (!body) return null;
    return el("section", { class: cls || "" }, el("h3", {}, title), el("p", { class: "text" }, body));
  }

  function code(title, text, cls) {
    if (!text) return null;
    return el("section", { class: "code " + (cls || "") }, el("h3", {}, title), el("pre", {}, el("code", {}, text)));
  }

  function render(p, hasResults) {
    root.replaceChildren();
    if (!p) {
      root.append(
        el("p", { class: "empty" }, hasResults ? "Select a finding in the list above to see its details." : "Run a scan to see findings here."),
      );
      return;
    }

    const badges = el(
      "div",
      { class: "badges" },
      el("span", { class: "badge sev-" + p.severity }, p.severityLabel),
      el("span", { class: "badge cat" }, p.categoryLabel),
      p.fixed && el("span", { class: "badge state ok" }, "Fix applied"),
      p.ignored && el("span", { class: "badge state" }, "Ignored"),
      p.stale && !p.fixed && el("span", { class: "badge state warn" }, "Code changed since scan"),
    );

    const loc = el("a", { href: "#", class: "location", title: "Open in editor", onclick: (e) => { e.preventDefault(); send("open", p.uid); } }, p.location);

    const meta = el(
      "dl",
      { class: "meta" },
      p.rule && el("dt", {}, "Rule"),
      p.rule && el("dd", {}, p.rule),
      p.source && el("dt", {}, "Source"),
      p.source && el("dd", {}, p.source),
      p.confidence > 0 && el("dt", {}, "Confidence"),
      p.confidence > 0 && el("dd", {}, Math.round(p.confidence * 100) + "%"),
      p.fixTime && el("dt", {}, "Fix time"),
      p.fixTime && el("dd", {}, p.fixTime),
    );

    const actions = el(
      "div",
      { class: "actions" },
      p.canApply && button("Apply fix", "applyFix", p.uid, true, "Replace the vulnerable code with the suggested fix (undo with Ctrl+Z)"),
      p.canDiff && button("Show diff", "showDiff", p.uid, !p.canApply),
      button("Open", "open", p.uid, !p.canApply && !p.canDiff),
      p.ignored ? button("Restore", "unignore", p.uid) : button("Ignore", "ignore", p.uid, false, "Hide this finding (remembered across scans)"),
      button("Copy", "copy", p.uid),
    );

    const fixIsCode = p.category === "code";
    root.append(
      el("h2", { class: "title" }, p.title),
      badges,
      loc,
      actions,
      p.aiMissing &&
        el("p", { class: "hint" }, "AI explanation and fix are not available for this scan. Enable “AI Security: Use AI” and set GROQ_API_KEY in backend/.env, then re-scan."),
      section("Why it's a problem", p.explanation),
      section("Attack scenario", p.attack),
      section("Business impact", p.impact),
      code(p.category === "dependency" ? "Installed" : "Vulnerable code", p.vulnerable, "vuln"),
      fixIsCode ? code(p.fixLabel, p.fix, "fix") : section(p.fixLabel, p.fix, "fix-text"),
      meta,
      p.references.length > 0 &&
        el(
          "section",
          {},
          el("h3", {}, "References"),
          el(
            "ul",
            { class: "refs" },
            ...p.references.map((url) =>
              el("li", {}, el("a", { href: "#", title: url, onclick: (e) => { e.preventDefault(); vscode.postMessage({ type: "openLink", url }); } }, url)),
            ),
          ),
        ),
    );
  }

  window.addEventListener("message", (e) => {
    const m = e.data;
    if (m && m.type === "show") {
      vscode.setState({ payload: m.payload, hasResults: m.hasResults });
      render(m.payload, m.hasResults);
    }
  });

  const saved = vscode.getState();
  if (saved) render(saved.payload, saved.hasResults);
  vscode.postMessage({ type: "ready" });
})();
