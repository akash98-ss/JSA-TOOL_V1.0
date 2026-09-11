#!/bin/bash
# scanner.sh — Phase 1 driver for the JSA (JS/CSS/HTML Analyzer) tool.
#
# Extraction is now delegated to extract.js (cheerio-based DOM parsing),
# which fixes the empty-js-dir bug: it catches inline <script>/<style>
# blocks, event-handler attributes, forms, comments, and response-header
# posture that the old regex-only grep pass silently missed.
#
# This script's job stays simple: call extract.js, then download every
# external JS/CSS URL it found, hunt for source maps, and run your
# signature rules (from your "JS file anylisis" notes) over everything —
# downloaded files AND inline_*.js / inline_*.css alike.

print_banner() {
    local CYAN="\e[36m"
    local GREEN="\e[32m"
    local YELLOW="\e[33m"
    local RESET="\e[0m"

    echo -e "${CYAN}"
    cat << "EOF"
       _  _____  _____   _____
      (_)/ ____|/ ____| / ____|
       _| (___ | (___  | (___   ___ __ _ _ __  _ __   ___ _ __
      | |\___ \\___ \  \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
      | |____) |___) | ____) | (_| (_| | | | | | | |  __/ |
      | |_____/_____/ |_____/ \___\__,_|_| |_|_| |_|\___|_|
     _/ |
    |__/
EOF
    echo -e "${RESET}"
    echo -e "${GREEN}:: Client-Side Asset Recon & Analysis (JS / CSS / HTML) ::${RESET}"
    echo -e "${YELLOW}>> DOM-based extraction via extract.js, signatures from JS file anylisis <<${RESET}\n"
}

print_banner

TARGET_URL="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="scan_results_$(date +%s)"

if [ -z "$TARGET_URL" ]; then
  echo "Usage: ./scanner.sh <https://target-website.com>  |  ./scanner.sh <local_file.html>"
  exit 1
fi

echo "[+] Target: $TARGET_URL"
echo "[+] Output dir: $OUTPUT_DIR"
echo

# --- Phase 1a: fetch the page with curl (proven to work), then hand the
# saved file to extract.js for parsing. This sidesteps a known undici/Node
# fetch() quirk on WSL2/NAT64 networks where fetch() doesn't fall back to
# IPv4 the way curl does, even with --dns-result-order set.
PAGE_HTML="$OUTPUT_DIR/page.html"
PAGE_HEADERS="$OUTPUT_DIR/page.headers.txt"
mkdir -p "$OUTPUT_DIR"

echo "[+] Fetching target with curl..."
curl -4 -sL "$TARGET_URL" -D "$PAGE_HEADERS" -o "$PAGE_HTML"
if [ ! -s "$PAGE_HTML" ]; then
    echo "[!] curl returned no content for $TARGET_URL — aborting."
    exit 1
fi

node --dns-result-order=ipv4first "$SCRIPT_DIR/extract.js" "$PAGE_HTML" "$OUTPUT_DIR" "$TARGET_URL" "$PAGE_HEADERS"
if [ $? -ne 0 ]; then
    echo "[!] extract.js failed — aborting."
    exit 1
fi
echo

# --- Phase 1b: download every external JS file it found, hunt source maps ---
if [ -s "$OUTPUT_DIR/js/ext_js.txt" ]; then
    echo "[+] Downloading external JavaScript..."
    while IFS= read -r link; do
        [ -z "$link" ] && continue
        filename=$(basename "${link%%\?*}")
        [ -z "$filename" ] && filename="unnamed_$(date +%s%N).js"
        echo "    -> $filename"
        curl -sL "$link" -o "$OUTPUT_DIR/js/$filename"

        map_url="${link}.map"
        map_status=$(curl -sL -o /dev/null -w "%{http_code}" "$map_url")
        if [ "$map_status" -eq 200 ]; then
            echo "       [!] Source map exposed! Downloading $filename.map"
            curl -sL "$map_url" -o "$OUTPUT_DIR/js/$filename.map"
        fi
    done < "$OUTPUT_DIR/js/ext_js.txt"
fi

# --- Phase 1c: same for external CSS ---
if [ -s "$OUTPUT_DIR/css/ext_css.txt" ]; then
    echo "[+] Downloading external CSS..."
    while IFS= read -r link; do
        [ -z "$link" ] && continue
        filename=$(basename "${link%%\?*}")
        [ -z "$filename" ] && filename="unnamed_$(date +%s%N).css"
        echo "    -> $filename"
        curl -sL "$link" -o "$OUTPUT_DIR/css/$filename"
    done < "$OUTPUT_DIR/css/ext_css.txt"
fi

# --- Phase 1d: run your signature rules over every JS/CSS file (external + inline alike) ---
echo
echo "[+] Applying signatures from your JS file anylisis..."
for f in "$OUTPUT_DIR"/js/*.js; do
    [ -e "$f" ] || continue
    [[ "$f" == *.map ]] && continue
    endpoints=$(grep -iEo '(/api/|/v[1-3]/|https?://[a-zA-Z0-9.-]+)[a-zA-Z0-9./_-]+' "$f")
    if [ -n "$endpoints" ]; then
        echo "    [*] $(basename "$f") — potential endpoints:"
        echo "$endpoints" | sort -u | sed 's/^/            - /'
    fi
done

echo
echo "[+] Scan complete."
echo "    manifest.json      -> full structured findings (JS/CSS/HTML)"
echo "    html_findings.txt  -> human-readable HTML-level findings"
echo "    js/ , css/         -> downloaded + inline assets, ready for signature/AST rules"
