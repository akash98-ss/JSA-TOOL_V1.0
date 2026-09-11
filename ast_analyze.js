#!/usr/bin/env node
/**
 * ast_analyze.js — Phase 2 of the JSA tool: real AST parsing of JS files
 * instead of regex/grep, per the plan (Babel for JS, structured traversal).
 *
 * Regex-based extraction (what scanner.sh's Phase 1d still did) breaks on
 * anything beyond simple literals: string concatenation, template literals,
 * minified/renamed variables, or code split across lines. Parsing into an
 * AST lets us reason about actual call expressions, assignments, and
 * argument types — a real step toward the source->sink tracing described
 * in the "JavaScript for Hackers" methodology, not a full taint-tracker,
 * but far more reliable than string matching.
 *
 * Usage:
 *   node ast_analyze.js <output_dir> <file1.js> [file2.js] ...
 *
 * Writes:
 *   <output_dir>/ast_findings.json  - structured findings per file
 *   <output_dir>/ast_findings.txt   - human-readable version
 */

const fs = require("fs");
const path = require("path");
const parser = require("@babel/parser");
const traverse = require("@babel/traverse").default;

const DANGEROUS_EXEC_SINKS = new Set(["eval", "Function"]);
const TIMER_FUNCS = new Set(["setTimeout", "setInterval"]);
const HTML_SINK_PROPS = new Set(["innerHTML", "outerHTML"]);
const SOURCE_PATTERNS = [
  "location.hash",
  "location.search",
  "location.href",
  "document.referrer",
  "window.name",
  "URLSearchParams",
  "document.URL",
  "document.location",
];

const SECRET_PATTERNS = [
  { name: "AWS Access Key", re: /AKIA[0-9A-Z]{16}/ },
  { name: "Google API Key", re: /AIza[0-9A-Za-z\-_]{35}/ },
  { name: "JWT", re: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/ },
  { name: "Generic Bearer Token", re: /Bearer\s+[A-Za-z0-9\-_.]{20,}/ },
  { name: "Slack Webhook", re: /hooks\.slack\.com\/services\/[A-Za-z0-9/_-]+/ },
];

const ENDPOINT_RE = /^(https?:\/\/[^\s"'`]+|\/api\/[^\s"'`]*|\/v[1-3]\/[^\s"'`]*)/i;

function containsSourcePattern(snippet) {
  return SOURCE_PATTERNS.some((p) => snippet.includes(p));
}

function analyzeFile(filePath) {
  const code = fs.readFileSync(filePath, "utf8");
  const findings = {
    file: filePath,
    parseError: null,
    execSinks: [],
    timerStringSinks: [],
    htmlSinks: [],
    documentWrite: [],
    insecurePostMessage: [],
    unvalidatedMessageListeners: [],
    dynamicNavigation: [],
    endpoints: new Set(),
    secrets: [],
  };

  let ast;
  try {
    ast = parser.parse(code, {
      sourceType: "unambiguous",
      errorRecovery: true,
      plugins: ["jsx", "typescript", "optionalChaining", "nullishCoalescingOperator"],
    });
  } catch (err) {
    findings.parseError = err.message;
    return findings;
  }

  const snippet = (node) => code.slice(node.start, node.end).replace(/\s+/g, " ").slice(0, 200);
  const line = (node) => (node.loc ? node.loc.start.line : "?");

  // Secret patterns + endpoint literals — scanning string/template literals
  // specifically (not the whole file blob) cuts down on false positives from
  // comments or unrelated text, and gives us exact line numbers.
  traverse(ast, {
    StringLiteral(p) {
      const v = p.node.value;
      if (ENDPOINT_RE.test(v)) findings.endpoints.add(v);
      SECRET_PATTERNS.forEach(({ name, re }) => {
        if (re.test(v)) {
          findings.secrets.push({ type: name, line: line(p.node), value: v.slice(0, 60) + (v.length > 60 ? "…" : "") });
        }
      });
    },
    TemplateElement(p) {
      const v = p.node.value.raw;
      if (ENDPOINT_RE.test(v)) findings.endpoints.add(v);
    },

    // eval(...) / new Function(...) / Function(...)
    CallExpression(p) {
      const callee = p.node.callee;
      const calleeName = callee.type === "Identifier" ? callee.name : null;

      if (calleeName && DANGEROUS_EXEC_SINKS.has(calleeName)) {
        findings.execSinks.push({ fn: calleeName, line: line(p.node), code: snippet(p.node) });
      }

      // setTimeout("...", n) / setInterval("...", n) — string arg means the
      // engine re-parses a string as code, same class of risk as eval.
      if (calleeName && TIMER_FUNCS.has(calleeName)) {
        const firstArg = p.node.arguments[0];
        if (firstArg && (firstArg.type === "StringLiteral" || firstArg.type === "TemplateLiteral")) {
          findings.timerStringSinks.push({ fn: calleeName, line: line(p.node), code: snippet(p.node) });
        }
      }

      // document.write(...) / document.writeln(...)
      if (
        callee.type === "MemberExpression" &&
        callee.object.type === "Identifier" &&
        callee.object.name === "document" &&
        callee.property.type === "Identifier" &&
        (callee.property.name === "write" || callee.property.name === "writeln")
      ) {
        const argSnippet = p.node.arguments[0] ? snippet(p.node.arguments[0]) : "";
        findings.documentWrite.push({
          line: line(p.node),
          code: snippet(p.node),
          sourceControlled: containsSourcePattern(argSnippet),
        });
      }

      // window.postMessage(data, "*") / el.contentWindow.postMessage(data, "*")
      if (
        callee.type === "MemberExpression" &&
        callee.property.type === "Identifier" &&
        callee.property.name === "postMessage"
      ) {
        const targetArg = p.node.arguments[1];
        if (targetArg && targetArg.type === "StringLiteral" && targetArg.value === "*") {
          findings.insecurePostMessage.push({ line: line(p.node), code: snippet(p.node) });
        }
      }

      // addEventListener("message", handler) — flag if handler body never
      // references .origin, a strong signal origin isn't being checked.
      if (
        callee.type === "MemberExpression" &&
        callee.property.type === "Identifier" &&
        callee.property.name === "addEventListener"
      ) {
        const evtArg = p.node.arguments[0];
        const handlerArg = p.node.arguments[1];
        if (
          evtArg &&
          evtArg.type === "StringLiteral" &&
          evtArg.value === "message" &&
          handlerArg &&
          (handlerArg.type === "FunctionExpression" || handlerArg.type === "ArrowFunctionExpression")
        ) {
          const bodyText = snippet(handlerArg);
          if (!/\.origin\b/.test(bodyText)) {
            findings.unvalidatedMessageListeners.push({ line: line(p.node), code: snippet(p.node) });
          }
        }
      }
    },

    // element.innerHTML = ... / element.outerHTML = ...
    AssignmentExpression(p) {
      const left = p.node.left;
      if (
        left.type === "MemberExpression" &&
        left.property.type === "Identifier" &&
        HTML_SINK_PROPS.has(left.property.name)
      ) {
        const rightSnippet = snippet(p.node.right);
        findings.htmlSinks.push({
          prop: left.property.name,
          line: line(p.node),
          code: snippet(p.node),
          sourceControlled: containsSourcePattern(rightSnippet),
        });
      }

      // location.href = ... / location = ... where the value isn't a plain
      // string literal (i.e. built dynamically) — worth a manual look.
      const isLocationTarget =
        (left.type === "Identifier" && left.name === "location") ||
        (left.type === "MemberExpression" &&
          left.object.type === "Identifier" &&
          left.object.name === "location" &&
          left.property.type === "Identifier" &&
          left.property.name === "href");
      if (isLocationTarget && p.node.right.type !== "StringLiteral") {
        findings.dynamicNavigation.push({ line: line(p.node), code: snippet(p.node) });
      }
    },
  });

  findings.endpoints = Array.from(findings.endpoints);
  return findings;
}

function main() {
  const [, , outputDir, ...files] = process.argv;
  if (!outputDir || files.length === 0) {
    console.error("Usage: node ast_analyze.js <output_dir> <file1.js> [file2.js] ...");
    process.exit(1);
  }
  fs.mkdirSync(outputDir, { recursive: true });

  const results = files
    .filter((f) => fs.existsSync(f) && !f.endsWith(".map"))
    .map((f) => analyzeFile(f));

  fs.writeFileSync(path.join(outputDir, "ast_findings.json"), JSON.stringify(results, null, 2));

  const lines = [];
  let totalFlags = 0;
  results.forEach((r) => {
    const flagCount =
      r.execSinks.length +
      r.timerStringSinks.length +
      r.htmlSinks.length +
      r.documentWrite.length +
      r.insecurePostMessage.length +
      r.unvalidatedMessageListeners.length +
      r.dynamicNavigation.length +
      r.secrets.length;
    if (flagCount === 0 && r.endpoints.length === 0 && !r.parseError) return;
    totalFlags += flagCount;

    lines.push(`=== ${r.file} ===`);
    if (r.parseError) {
      lines.push(`  [!] Parse error (file may be non-JS or heavily obfuscated): ${r.parseError}`);
    }
    if (r.endpoints.length) {
      lines.push(`  Endpoints/paths found (${r.endpoints.length}):`);
      r.endpoints.slice(0, 40).forEach((e) => lines.push(`    - ${e}`));
    }
    if (r.secrets.length) {
      lines.push(`  [!] Possible hardcoded secrets (${r.secrets.length}):`);
      r.secrets.forEach((s) => lines.push(`    - line ${s.line}: ${s.type} — ${s.value}`));
    }
    if (r.execSinks.length) {
      lines.push(`  [!] eval()/Function() calls (${r.execSinks.length}) — verify argument isn't attacker-influenced:`);
      r.execSinks.forEach((s) => lines.push(`    - line ${s.line}: ${s.code}`));
    }
    if (r.timerStringSinks.length) {
      lines.push(`  [!] setTimeout/setInterval called with a string argument (${r.timerStringSinks.length}):`);
      r.timerStringSinks.forEach((s) => lines.push(`    - line ${s.line}: ${s.code}`));
    }
    if (r.htmlSinks.length) {
      lines.push(`  [!] innerHTML/outerHTML assignments (${r.htmlSinks.length}):`);
      r.htmlSinks.forEach((s) =>
        lines.push(
          `    - line ${s.line}${s.sourceControlled ? "  [SOURCE-CONTROLLED VALUE — HIGH PRIORITY]" : ""}: ${s.code}`
        )
      );
    }
    if (r.documentWrite.length) {
      lines.push(`  [!] document.write()/writeln() calls (${r.documentWrite.length}):`);
      r.documentWrite.forEach((s) =>
        lines.push(`    - line ${s.line}${s.sourceControlled ? "  [SOURCE-CONTROLLED VALUE]" : ""}: ${s.code}`)
      );
    }
    if (r.insecurePostMessage.length) {
      lines.push(`  [!] postMessage() with wildcard "*" target origin (${r.insecurePostMessage.length}):`);
      r.insecurePostMessage.forEach((s) => lines.push(`    - line ${s.line}: ${s.code}`));
    }
    if (r.unvalidatedMessageListeners.length) {
      lines.push(`  [!] "message" event listener(s) with no visible .origin check (${r.unvalidatedMessageListeners.length}):`);
      r.unvalidatedMessageListeners.forEach((s) => lines.push(`    - line ${s.line}: ${s.code}`));
    }
    if (r.dynamicNavigation.length) {
      lines.push(`  Dynamic location/navigation assignments (${r.dynamicNavigation.length}, review manually):`);
      r.dynamicNavigation.forEach((s) => lines.push(`    - line ${s.line}: ${s.code}`));
    }
    lines.push("");
  });

  if (lines.length === 0) {
    lines.push("No AST-level findings across the provided files.");
  }
  fs.writeFileSync(path.join(outputDir, "ast_findings.txt"), lines.join("\n") + "\n");

  console.log(`[+] AST analysis complete: ${results.length} file(s) analyzed, ${totalFlags} flag(s) raised.`);
  console.log(`[+] Details: ${path.join(outputDir, "ast_findings.txt")}`);
}

main();
