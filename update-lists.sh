#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# update-lists.sh — Fetch latest malicious package advisories from
#                   GitHub Advisory Database and update blocklists
#
# Source:  https://api.github.com/advisories?type=malware
# Updates: lists/ folder in this repository
# Safe:    API queries only — no package downloads, no code execution
#
# Designed for GitHub Actions (non-interactive).
# Can also run locally:
#   GITHUB_TOKEN=ghp_xxx ./update-lists.sh
# ═══════════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LISTS_DIR="$SCRIPT_DIR/lists"
GITHUB_API="https://api.github.com/advisories"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
LAST_UPDATED_FILE="$SCRIPT_DIR/LAST_UPDATED.txt"

# ── Read last check date (for incremental updates) ───────────────
LAST_CHECK=""
if [[ -f "$LAST_UPDATED_FILE" ]]; then
    LAST_CHECK=$(grep '^Last checked:' "$LAST_UPDATED_FILE" | head -1 | sed 's/Last checked: //')
fi

# ── Output helpers ────────────────────────────────────────────────
info()   { echo "[INFO] $*"; }
ok()     { echo "[PASS] $*"; }
warn()   { echo "[WARN] $*"; }
fail()   { echo "[FAIL] $*"; }

# ── Prerequisites ─────────────────────────────────────────────────
for cmd in curl jq; do
    command -v "$cmd" &>/dev/null || { fail "Required: $cmd"; exit 1; }
done
[[ -d "$LISTS_DIR" ]] || { fail "Missing directory: $LISTS_DIR"; exit 1; }

# ── curl wrapper (handles optional auth) ──────────────────────────
github_curl() {
    if [[ -n "${GITHUB_TOKEN:-}" ]]; then
        curl -sS -H "Accept: application/vnd.github+json" \
             -H "Authorization: Bearer $GITHUB_TOKEN" "$@"
    else
        curl -sS -H "Accept: application/vnd.github+json" "$@"
    fi
}

info "GGT Blocklist Updater — $(date '+%Y-%m-%d %H:%M:%S')"
if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    info "Authenticated — rate limit: 5000 req/hr"
else
    info "Anonymous — rate limit: 60 req/hr"
fi

# ── Mode: incremental (default) or full ───────────────────────────
FULL_SCAN=false
if [[ "${1:-}" == "--full" ]]; then
    FULL_SCAN=true
    info "Mode: FULL SCAN (all pages)"
elif [[ -n "$LAST_CHECK" ]]; then
    info "Mode: incremental (since $LAST_CHECK)"
else
    FULL_SCAN=true
    info "Mode: FULL SCAN (first run)"
fi

# ═══════════════════════════════════════════════════════════════════
#  Fetch all malware advisories for a given ecosystem
# ═══════════════════════════════════════════════════════════════════
fetch_malware() {
    local ecosystem="$1"
    local outfile="$2"
    local raw="$WORK/${ecosystem}_raw.txt"
    : > "$raw"
    local page=1 total_advisories=0

    # Build query: incremental (updated since last check) or full
    local base_query="type=malware&ecosystem=$ecosystem&per_page=100"
    if [[ "$FULL_SCAN" == "false" && -n "$LAST_CHECK" ]]; then
        base_query="${base_query}&updated=${LAST_CHECK}"
        info "Fetching $ecosystem advisories updated since $LAST_CHECK..."
    else
        info "Fetching ALL $ecosystem malware advisories..."
    fi

    while true; do
        local tmp="$WORK/resp_${ecosystem}_${page}.json"
        local http_code
        http_code=$(github_curl -o "$tmp" -w "%{http_code}" \
            "$GITHUB_API?${base_query}&page=$page" 2>/dev/null) || true

        if [[ "$http_code" == "403" ]]; then
            warn "Rate limited at page $page"
            break
        elif [[ "$http_code" != "200" ]]; then
            warn "HTTP $http_code at page $page — stopping"
            break
        fi

        local count
        count=$(jq 'if type=="array" then length else 0 end' "$tmp" 2>/dev/null || echo 0)
        [[ "$count" -eq 0 ]] && break

        jq -r '.[].vulnerabilities[]?.package.name // empty' "$tmp" >> "$raw" 2>/dev/null
        total_advisories=$((total_advisories + count))
        info "  Page $page — $count advisories"

        [[ "$count" -lt 100 ]] && break
        ((page++))
        sleep 1
    done

    info "  Total advisories scanned: $total_advisories"
    sort -u "$raw" | grep -v '^$' > "$outfile" || true
}

# ═══════════════════════════════════════════════════════════════════
#  Update a single blocklist file with new entries (plaintext)
# ═══════════════════════════════════════════════════════════════════
update_blocklist() {
    local file="$1"
    local new_file="$2"
    local added=0

    while IFS= read -r pkg; do
        [[ -z "$pkg" ]] && continue
        if ! grep -qxF -- "$pkg" "$file" 2>/dev/null; then
            echo "$pkg" >> "$file"
            ((added++))
        fi
    done < "$new_file"

    echo "$added"
}

# ═══════════════════════════════════════════════════════════════════
#  Process one ecosystem
# ═══════════════════════════════════════════════════════════════════
process_ecosystem() {
    local ecosystem="$1"
    local list_filename="$2"
    local list_file="$LISTS_DIR/$list_filename"

    if [[ ! -f "$list_file" ]]; then
        warn "$list_filename not found — skipping"
        return
    fi

    local new_file="$WORK/${ecosystem}_new.txt"
    fetch_malware "$ecosystem" "$new_file"

    local total
    total=$(wc -l < "$new_file" 2>/dev/null | tr -d ' ')
    info "Unique malicious packages found: $total"

    if [[ "$total" -gt 0 ]]; then
        local added
        added=$(update_blocklist "$list_file" "$new_file")

        if [[ "$added" -gt 0 ]]; then
            ok "+$added new packages added to $list_filename"
        else
            ok "All $total packages already in blocklist — up to date"
        fi
    else
        warn "No malware data received from API"
    fi
}

# ═══════════════════════════════════════════════════════════════════
#  Run
# ═══════════════════════════════════════════════════════════════════
process_ecosystem "npm"   "malicious-npm-packages.txt"
process_ecosystem "nuget" "malicious-nuget-packages.txt"

# ═══════════════════════════════════════════════════════════════════
#  Summary + timestamp
# ═══════════════════════════════════════════════════════════════════
count_entries() { grep -cv '^#\|^$' "$1" 2>/dev/null || echo 0; }

info "npm: $(count_entries "$LISTS_DIR/malicious-npm-packages.txt") entries"
info "nuget: $(count_entries "$LISTS_DIR/malicious-nuget-packages.txt") entries"

# Write last-updated timestamp
TS=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
cat > "$SCRIPT_DIR/LAST_UPDATED.txt" <<EOF
Last checked: $TS
npm packages: $(count_entries "$LISTS_DIR/malicious-npm-packages.txt")
nuget packages: $(count_entries "$LISTS_DIR/malicious-nuget-packages.txt")
Source: GitHub Advisory Database (type=malware)
EOF
info "Done — $TS"
