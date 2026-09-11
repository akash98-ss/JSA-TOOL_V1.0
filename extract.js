#!/usr/bin/env node
/**
 * extract.js — HTML asset extractor for the JSA (JS/CSS Analyzer) tool.
 *
 * Fixes the root cause you hit with the grep-based Bash extractor:
 * regex against raw HTML can't reliably see inline <script>/<style> blocks,
 * self-closing tags, single-quoted attrs, or weird whitespace. This uses a
 * real DOM parser (cheerio) so extraction is structural, not pattern-guessed.
 *
 * Usage:
 *   node extract.js <url> <output_dir>
 *
 * Output (written into <output_dir>):
 *   manifest.json        - full structured result (for future AST phase)
 *   js/ext_*.txt          - list of resolved external JS URLs (one per line)
 *   css/ext_*.txt         - list of resolved external CSS URLs
 *   js/inline_1.js, ...   - each inline <script> block, saved separately
 *   css/inline_1.css, ... - each inline <style> block, saved separately
 *
 * scanner.sh then just downloads every URL in ext_js.txt / ext_css.txt and
 * runs its grep/signature rules over both the downloaded files AND the
 * inline_*.js / inline_*.css files exactly the same way.
 */

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");

async function main() {
  const [, , targetUrl, outputDirArg, baseUrlOverride, headersFileArg] = process.argv;

  if (!targetUrl) {
    console.error("Usage: node extract.js <url> <output_dir>");
    process.exit(1);
  }

  const outputDir = outputDirArg || `scan_results_${Date.now()}`;
  const jsDir = path.join(outputDir, "js");
  const cssDir = path.join(outputDir, "css");
  for (const dir of [outputDir, jsDir, cssDir]) {
    fs.mkdirSync(dir, { recursive: true });
  }

  let html;
  let responseHeaders = {};
  const isRemote = /^https?:\/\//i.test(targetUrl);

  if (isRemote) {
    try {
      const res = await fetch(targetUrl, { redirect: "follow" });
      html = await res.text();
      res.headers.forEach((value, key) => (responseHeaders[key] = value));
    } catch (err) {
      console.error(`[!] Failed to fetch ${targetUrl}: ${err.message}`);
      if (err.cause) {
        console.error(`    Underlying cause: ${err.cause.code || err.cause.message || err.cause}`);
      }
      console.error(`    Try: curl -v "${targetUrl}"  to check if this is a DNS/TLS/network issue vs. a code bug.`);
      console.error(`    Or use curl to fetch to a file and pass that file path + --base to this script instead of a URL.`);
      process.exit(1);
    }
  } else {
    // Treat as a local file path — lets you point this at an already-saved
    // HTML dump (e.g. from curl or Burp) without hitting the network at all.
    // This is also the recommended path on networks where Node's fetch()
    // (undici) fails to fall back to IPv4 the way curl does.
    try {
      html = fs.readFileSync(targetUrl, "utf8");
    } catch (err) {
      console.error(`[!] Failed to read local file ${targetUrl}: ${err.message}`);
      process.exit(1);
    }

    // Optional headers dump (curl -D -) so security-header checks still work
    // even though we bypassed fetch() entirely for the actual page content.
    if (headersFileArg) {
      try {
        const raw = fs.readFileSync(headersFileArg, "utf8");
        raw.split(/\r?\n/).forEach((line) => {
          const idx = line.indexOf(":");
          if (idx > 0) {
            const key = line.slice(0, idx).trim().toLowerCase();
            const value = line.slice(idx + 1).trim();
            if (key) responseHeaders[key] = value;
          }
        });
      } catch (err) {
        console.error(`[!] Could not read headers file ${headersFileArg}: ${err.message} (continuing without header checks)`);
      }
    }
  }

  const $ = cheerio.load(html);
  // Use an explicit --base override when given (needed when reading from a
  // local file, since there's no real request URL to resolve relative links
  // against). Falls back to the target URL itself when it's a real URL, or
  // a harmless dummy when neither is available.
  const effectiveBase = baseUrlOverride || (isRemote ? targetUrl : null);
  const base = effectiveBase ? new URL(effectiveBase) : new URL("http://local.invalid/");

  const resolve = (link) => {
    try {
      return new URL(link, base).toString();
    } catch {
      return null;
    }
  };

  // --- External + inline <script> ---
  const externalJs = [];
  const inlineJs = [];

  $("script").each((_, el) => {
    const src = $(el).attr("src");
    if (src) {
      const resolved = resolve(src);
      if (resolved) externalJs.push(resolved);
    } else {
      const content = $(el).html();
      if (content && content.trim().length > 0) {
        inlineJs.push(content);
      }
    }
  });

  // --- External + inline CSS ---
  const externalCss = [];
  const inlineCss = [];

  $('link[rel="stylesheet"]').each((_, el) => {
    const href = $(el).attr("href");
    if (href) {
      const resolved = resolve(href);
      if (resolved) externalCss.push(resolved);
    }
  });

  $("style").each((_, el) => {
    const content = $(el).html();
    if (content && content.trim().length > 0) {
      inlineCss.push(content);
    }
  });

  // Also catch CSS url(...) values inside inline style="" attributes
  // and any <style> blocks that reference external assets via @import.
  const inlineStyleAttrs = [];
  $("[style]").each((_, el) => {
    const val = $(el).attr("style");
    if (val && /url\(|expression\(/i.test(val)) {
      inlineStyleAttrs.push({ tag: el.tagName, style: val });
    }
  });

  // --- HTML-level analysis (the page itself, not just what it links to) ---

  // HTML comments — frequent home for internal paths, TODOs, dead admin links,
  // commented-out debug code, developer names.
  const comments = [];
  $("*")
    .contents()
    .each((_, node) => {
      if (node.type === "comment") {
        const text = node.data.trim();
        if (text.length > 0) comments.push(text);
      }
    });
  // cheerio only walks contents of matched elements above; also grab
  // top-level/document comments that $("*") misses (e.g. before <html>).
  const rawCommentMatches = html.match(/<!--([\s\S]*?)-->/g) || [];
  rawCommentMatches.forEach((c) => {
    const inner = c.replace(/^<!--/, "").replace(/-->$/, "").trim();
    if (inner && !comments.includes(inner)) comments.push(inner);
  });

  // Forms — action/method, and whether sensitive fields look exposed.
  const forms = [];
  $("form").each((_, el) => {
    const action = $(el).attr("action") || "(same page)";
    const method = ($(el).attr("method") || "GET").toUpperCase();
    const inputs = [];
    $(el)
      .find("input")
      .each((__, input) => {
        inputs.push({
          name: $(input).attr("name") || null,
          type: $(input).attr("type") || "text",
          autocomplete: $(input).attr("autocomplete") || null,
          hasValue: !!$(input).attr("value"),
        });
      });
    forms.push({ action, method, inputs });
  });

  // Password fields that don't disable autocomplete — low-severity but a
  // classic finding for a checklist-style report.
  const passwordFieldsWithoutAutocompleteOff = [];
  $('input[type="password"]').each((_, el) => {
    const ac = ($(el).attr("autocomplete") || "").toLowerCase();
    if (ac !== "off" && ac !== "new-password") {
      passwordFieldsWithoutAutocompleteOff.push($(el).attr("name") || "(unnamed)");
    }
  });

  // Inline event-handler attributes — onclick, onerror, onload, etc.
  // Not inherently vulnerable, but each one is a place where attacker-
  // controlled data reaching an attribute could execute script, and it's
  // exactly the kind of thing "JavaScript for Hackers"-style manual review
  // flags for a closer look.
  const EVENT_ATTR_RE = /^on[a-z]+$/i;
  const inlineEventHandlers = [];
  $("*").each((_, el) => {
    if (!el.attribs) return;
    for (const attr of Object.keys(el.attribs)) {
      if (EVENT_ATTR_RE.test(attr)) {
        inlineEventHandlers.push({
          tag: el.tagName,
          attr,
          value: el.attribs[attr],
        });
      }
    }
  });

  // Meta tags — generator (framework/CMS fingerprinting) and any CSP
  // delivered via <meta> rather than a header.
  const meta = [];
  $("meta").each((_, el) => {
    const name = $(el).attr("name") || $(el).attr("http-equiv");
    const content = $(el).attr("content");
    if (name) meta.push({ name, content });
  });
  const generatorTag = meta.find((m) => (m.name || "").toLowerCase() === "generator");
  const metaCsp = meta.find(
    (m) => (m.name || "").toLowerCase() === "content-security-policy"
  );

  // Mixed content — hardcoded http:// resource refs on an https:// page.
  const mixedContent = [];
  if (base.protocol === "https:") {
    $("[src], [href]").each((_, el) => {
      const val = $(el).attr("src") || $(el).attr("href");
      if (val && /^http:\/\//i.test(val)) mixedContent.push(val);
    });
  }

  // Response-header security posture — cheap wins for the report.
  const securityHeaderFindings = [];
  const headerChecks = [
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "strict-transport-security",
    "referrer-policy",
  ];
  headerChecks.forEach((h) => {
    if (!responseHeaders[h]) securityHeaderFindings.push(`Missing header: ${h}`);
  });
  const setCookie = responseHeaders["set-cookie"];
  if (setCookie) {
    if (!/httponly/i.test(setCookie)) securityHeaderFindings.push("Cookie missing HttpOnly flag");
    if (!/secure/i.test(setCookie) && base.protocol === "https:")
      securityHeaderFindings.push("Cookie missing Secure flag");
    if (!/samesite/i.test(setCookie)) securityHeaderFindings.push("Cookie missing SameSite flag");
  }

  // --- Write outputs ---
  fs.writeFileSync(
    path.join(jsDir, "ext_js.txt"),
    externalJs.join("\n") + (externalJs.length ? "\n" : "")
  );
  fs.writeFileSync(
    path.join(cssDir, "ext_css.txt"),
    externalCss.join("\n") + (externalCss.length ? "\n" : "")
  );

  inlineJs.forEach((content, i) => {
    fs.writeFileSync(path.join(jsDir, `inline_${i + 1}.js`), content);
  });
  inlineCss.forEach((content, i) => {
    fs.writeFileSync(path.join(cssDir, `inline_${i + 1}.css`), content);
  });

  const manifest = {
    target: targetUrl,
    scannedAt: new Date().toISOString(),
    externalJsCount: externalJs.length,
    externalCssCount: externalCss.length,
    inlineJsCount: inlineJs.length,
    inlineCssCount: inlineCss.length,
    externalJs,
    externalCss,
    inlineStyleAttrsFlagged: inlineStyleAttrs,
    html: {
      commentCount: comments.length,
      comments,
      forms,
      passwordFieldsWithoutAutocompleteOff,
      inlineEventHandlers,
      meta,
      generatorTag: generatorTag || null,
      metaCsp: metaCsp || null,
      mixedContent,
      securityHeaderFindings,
      responseHeadersSeen: Object.keys(responseHeaders),
    },
  };
  fs.writeFileSync(
    path.join(outputDir, "manifest.json"),
    JSON.stringify(manifest, null, 2)
  );

  // Human-scannable HTML findings report, separate from the JS/CSS asset dirs.
  const reportLines = [];
  reportLines.push(`HTML analysis for ${targetUrl}`);
  reportLines.push("=".repeat(40));
  reportLines.push(`Comments found: ${comments.length}`);
  comments.slice(0, 50).forEach((c) => reportLines.push(`  - ${c.replace(/\s+/g, " ").slice(0, 200)}`));
  reportLines.push("");
  reportLines.push(`Forms found: ${forms.length}`);
  forms.forEach((f, i) => {
    reportLines.push(`  [${i + 1}] ${f.method} -> ${f.action}`);
    f.inputs.forEach((inp) =>
      reportLines.push(`        input name=${inp.name} type=${inp.type} autocomplete=${inp.autocomplete}`)
    );
  });
  reportLines.push("");
  if (passwordFieldsWithoutAutocompleteOff.length) {
    reportLines.push(
      `[!] Password field(s) without autocomplete=off: ${passwordFieldsWithoutAutocompleteOff.join(", ")}`
    );
  }
  if (inlineEventHandlers.length) {
    reportLines.push(`Inline event handler attributes: ${inlineEventHandlers.length}`);
    inlineEventHandlers.slice(0, 30).forEach((h) =>
      reportLines.push(`  - <${h.tag} ${h.attr}="${h.value.slice(0, 120)}">`)
    );
  }
  if (generatorTag) {
    reportLines.push(`[!] Generator/CMS fingerprint exposed: ${generatorTag.content}`);
  }
  if (mixedContent.length) {
    reportLines.push(`[!] Mixed content (http:// on https page): ${mixedContent.length}`);
    mixedContent.forEach((m) => reportLines.push(`  - ${m}`));
  }
  if (securityHeaderFindings.length) {
    reportLines.push(`Security header findings:`);
    securityHeaderFindings.forEach((f) => reportLines.push(`  - ${f}`));
  }
  fs.writeFileSync(path.join(outputDir, "html_findings.txt"), reportLines.join("\n") + "\n");

  // --- Console summary for scanner.sh to eyeball ---
  console.log(`[+] External JS found:    ${externalJs.length}`);
  console.log(`[+] Inline <script> found: ${inlineJs.length}`);
  console.log(`[+] External CSS found:   ${externalCss.length}`);
  console.log(`[+] Inline <style> found:  ${inlineCss.length}`);
  console.log(`[+] HTML comments found:  ${comments.length}`);
  console.log(`[+] Forms found:          ${forms.length}`);
  console.log(`[+] Inline event handlers:${inlineEventHandlers.length}`);
  if (passwordFieldsWithoutAutocompleteOff.length) {
    console.log(`[!] Password field(s) without autocomplete=off`);
  }
  if (generatorTag) {
    console.log(`[!] Generator/CMS tag exposed: ${generatorTag.content}`);
  }
  if (mixedContent.length) {
    console.log(`[!] ${mixedContent.length} mixed-content (http://) reference(s) on an https page`);
  }
  if (securityHeaderFindings.length) {
    console.log(`[!] ${securityHeaderFindings.length} response-header security finding(s) — see html_findings.txt`);
  }
  if (inlineStyleAttrs.length) {
    console.log(
      `[!] ${inlineStyleAttrs.length} inline style="" attribute(s) contain url()/expression() — worth a manual look (clickjacking / legacy CSS-JS)`
    );
  }
  console.log(`[+] Manifest written to ${path.join(outputDir, "manifest.json")}`);
  console.log(`[+] HTML findings written to ${path.join(outputDir, "html_findings.txt")}`);
}

main();
