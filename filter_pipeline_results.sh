#!/bin/bash

# TODO: Not working for all cases.

# Enhanced Pipeline Results Filter Script
# Mimics the behavior of pipeline-results-service.ts
#
# This script filters Veracode Pipeline Scan results by comparing them against
# Policy/Platform scan findings to exclude mitigated or previously-scanned findings.
#
# Dependencies: httpie, jq, curl
# Best suited for veracode/api-signing container or systems with httpie installed

set -e

#############################################
# Configuration and Defaults
#############################################

DEFAULT_LINE_NUMBER_SLOP=3
DEFAULT_INPUT_FILE="results.json"
DEFAULT_FILTER="all_results"
DEBUG_MODE=false
FAIL_ON_POLICY=false

LINE_NUMBER_SLOP=$DEFAULT_LINE_NUMBER_SLOP
FILTER_TYPE=$DEFAULT_FILTER

#############################################
# Helper Functions
#############################################

debug_log() {
    if [ "$DEBUG_MODE" = true ]; then
        echo "[DEBUG] $*" >&2
    fi
}

print_usage() {
    cat << EOF
Usage: $0 <vid> <vkey> <appname> [options]

Required arguments:
  vid                              Veracode API ID
  vkey                             Veracode API Key
  appname                          Veracode application name

Optional arguments:
  --line-number-slop <n>           Line number slop for matching (default: 3)
  --filter <type>                  Filter type (default: "all_results")
  --input-file <file>              Input pipeline results file (default: "results.json")
  --output-file <file>             Output file (default: overwrites input file)
  --fail-on-policy                 Exit with error code if policy violations found
  --debug                          Enable debug logging

Available filter options:
  all_results                      All findings
  policy_violations                Only policy violating findings
  unmitigated_results              Exclude mitigated findings
  unmitigated_policy_violations    Unmitigated policy violations only
  new_findings                     New findings only
  new_policy_violations            New policy violations only

Examples:
  $0 "\$VID" "\$VKEY" "MyApp" --filter unmitigated_results --input-file results.json
  $0 "\$VID" "\$VKEY" "MyApp" --filter policy_violations --debug
  $0 "\$VID" "\$VKEY" "MyApp" --line-number-slop 5 --fail-on-policy

EOF
}

print_results() {    
    echo "=============================================="
    echo "Pipeline findings: $1"
    echo "Mitigated findings: $2"
    echo "Filtered pipeline findings: $3"
    echo "=============================================="
}

#############################################
# Parse Command Line Arguments
#############################################

if [ $# -eq 0 ]; then
    print_usage
    exit 1
fi

# Required arguments
export VERACODE_API_KEY_ID="${1:-${VERACODE_API_KEY_ID}}"
export VERACODE_API_KEY_SECRET="${2:-${VERACODE_API_KEY_SECRET}}"
APP_NAME="${3}"

# Shift past the first 3 required arguments
shift 3 2>/dev/null || true

# Parse optional arguments
INPUT_FILE="$DEFAULT_INPUT_FILE"
OUTPUT_FILE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --line-number-slop) LINE_NUMBER_SLOP="$2"; shift 2 ;;
        --filter) FILTER_TYPE="$2"; shift 2 ;;
        --input-file) INPUT_FILE="$2"; shift 2 ;;
        --output-file) OUTPUT_FILE="$2"; shift 2 ;;
        --fail-on-policy) FAIL_ON_POLICY=true; shift ;;
        --debug) DEBUG_MODE=true; shift ;;
        --help|-h) print_usage; exit 0 ;;
        *) echo "Unknown argument: $1"; print_usage; exit 1 ;;
    esac
done

# Validate required arguments
if [ -z "$VERACODE_API_KEY_ID" ] || [ -z "$VERACODE_API_KEY_SECRET" ] || [ -z "$APP_NAME" ]; then
    echo "Error: vid, vkey, and appname are required"
    print_usage
    exit 1
fi

# Set output file to input file if not specified (overwrite mode)
if [ -z "$OUTPUT_FILE" ]; then
    OUTPUT_FILE="$INPUT_FILE"
fi

# Validate input file exists
if [ ! -f "$INPUT_FILE" ]; then
    echo "Error: Input file '$INPUT_FILE' not found"
    exit 1
fi

#############################################
# Display Configuration
#############################################

echo "############################################"
echo "Configuration:"
echo "  Application: $APP_NAME"
echo "  Input file: $INPUT_FILE"
echo "  Output file: $OUTPUT_FILE"
echo "  Filter type: $FILTER_TYPE"
echo "  Line number slop: $LINE_NUMBER_SLOP"
echo "  Fail on policy: $FAIL_ON_POLICY"
echo "  Debug mode: $DEBUG_MODE"
echo "############################################"
echo ""

debug_log "VERACODE_API_KEY_ID (masked): ${VERACODE_API_KEY_ID:0:8}..."
debug_log "Input file size: $(wc -c < "$INPUT_FILE" | tr -d ' ') bytes"

#############################################
# Read and Validate Pipeline Results
#############################################

debug_log "Reading pipeline results from: $INPUT_FILE"

# Count findings in pipeline results
PIPELINE_FINDINGS_COUNT=$(jq '.findings | length' "$INPUT_FILE" 2>/dev/null || echo "0")

if [ -z "$PIPELINE_FINDINGS_COUNT" ] || [ "$PIPELINE_FINDINGS_COUNT" = "null" ]; then
    echo "Error: Could not parse pipeline results file"
    exit 1
fi

echo "Pipeline findings: ${PIPELINE_FINDINGS_COUNT}"
debug_log "Scan ID: $(jq -r '.scan_id // "N/A"' "$INPUT_FILE")"

#############################################
# Early Exit Optimization
#############################################

# For 'all_results' and 'policy_violations', we don't need to fetch from Veracode
# because we're not filtering out mitigated findings
if [ "$PIPELINE_FINDINGS_COUNT" -eq 0 ] || \
   [ "$FILTER_TYPE" = "all_results" ] || \
   [ "$FILTER_TYPE" = "policy_violations" ]; then
    
    debug_log "========================================"
    debug_log "Skipping Veracode API calls - early exit condition met"
    debug_log "  Reason: Filter '$FILTER_TYPE' does not require Veracode API calls"
    debug_log "  - Pipeline findings count: $PIPELINE_FINDINGS_COUNT"
    debug_log "  - Filter type: $FILTER_TYPE"
    debug_log ""
    debug_log "NOTE: To fetch and filter against Veracode platform findings, use:"
    debug_log "  - unmitigated_results"
    debug_log "  - unmitigated_policy_violations"
    debug_log "  - new_findings"
    debug_log "  - new_policy_violations"
    debug_log "========================================"
    
    # Copy input to output
    if [ "$INPUT_FILE" != "$OUTPUT_FILE" ]; then
        cp "$INPUT_FILE" "$OUTPUT_FILE"
    fi
    
    echo "Results written to $OUTPUT_FILE"
    print_results "$PIPELINE_FINDINGS_COUNT" 0 "$PIPELINE_FINDINGS_COUNT"
    
    if [ "$PIPELINE_FINDINGS_COUNT" -eq 0 ]; then
        exit 0
    else
        if [ "$FAIL_ON_POLICY" = true ]; then
            echo "Pipeline scan results contain findings."
            exit 1
        fi
        exit 0
    fi
fi

#############################################
# Fetch Application GUID
#############################################

debug_log "========================================"
debug_log "Fetching application from Veracode API"
debug_log "Application name: $APP_NAME"

TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

APP_RESPONSE_FILE="$TEMP_DIR/app_response.json"

echo "Fetching application GUID..."
debug_log "Calling: GET https://api.veracode.com/appsec/v1/applications?name=$APP_NAME"

if ! http --auth-type veracode_hmac GET "https://api.veracode.com/appsec/v1/applications?name=$(printf %s "$APP_NAME" | jq -sRr @uri)" > "$APP_RESPONSE_FILE" 2>/dev/null; then
    echo "Error: Failed to fetch application from Veracode API"
    debug_log "API call failed"
    echo "Skipping policy flaws fetch. Copying pipeline results without filtering."
    cp "$INPUT_FILE" "$OUTPUT_FILE"
    print_results "$PIPELINE_FINDINGS_COUNT" 0 "$PIPELINE_FINDINGS_COUNT"
    exit 0
fi

GUID=$(jq -r '._embedded.applications[0].guid // empty' "$APP_RESPONSE_FILE")

debug_log "API response received"
debug_log "Total applications: $(jq '._embedded.applications | length' "$APP_RESPONSE_FILE")"

if [ -z "$GUID" ] || [ "$GUID" = "null" ]; then
    echo "No application found with name '$APP_NAME'"
    echo "Skipping policy flaws fetch. Copying pipeline results without filtering."
    cp "$INPUT_FILE" "$OUTPUT_FILE"
    print_results "$PIPELINE_FINDINGS_COUNT" 0 "$PIPELINE_FINDINGS_COUNT"
    exit 0
fi

echo "Application GUID: ${GUID}"
debug_log "Application profile: $(jq -r '._embedded.applications[0].profile.name // "N/A"' "$APP_RESPONSE_FILE")"

#############################################
# Fetch Policy Findings
#############################################

echo "Fetching policy findings..."
debug_log "Calling: GET https://api.veracode.com/appsec/v2/applications/${GUID}/findings?scan_type=STATIC&size=500"

FINDINGS_OUTPUT_FILE="$TEMP_DIR/policy_findings.json"
FINDINGS_PAGE_0="$TEMP_DIR/findings_p0.json"

# Fetch first page
if ! http --auth-type veracode_hmac GET "https://api.veracode.com/appsec/v2/applications/${GUID}/findings?scan_type=STATIC&size=500" > "$FINDINGS_PAGE_0" 2>/dev/null; then
    echo "Error: Failed to fetch findings from Veracode API"
    echo "Copying pipeline results without filtering."
    cp "$INPUT_FILE" "$OUTPUT_FILE"
    print_results "$PIPELINE_FINDINGS_COUNT" 0 "$PIPELINE_FINDINGS_COUNT"
    exit 0
fi

TOTAL_PAGES=$(jq -r '.page.total_pages // 1' "$FINDINGS_PAGE_0")
TOTAL_ELEMENTS=$(jq -r '.page.total_elements // 0' "$FINDINGS_PAGE_0")

debug_log "Retrieved ${TOTAL_ELEMENTS} policy findings (${TOTAL_PAGES} pages)"

# If only one page, we're done
if [ "$TOTAL_PAGES" -eq 1 ]; then
    mv "$FINDINGS_PAGE_0" "$FINDINGS_OUTPUT_FILE"
else
    debug_log "Fetching additional pages..."
    
    # Fetch remaining pages
    for ((i=1; i<TOTAL_PAGES; i++)); do
        debug_log "Fetching page $i..."
        FINDINGS_TMP="$TEMP_DIR/findings_tmp.json"
        FINDINGS_PREV="$TEMP_DIR/findings_p$((i-1)).json"
        FINDINGS_CURRENT="$TEMP_DIR/findings_p${i}.json"
        
        http --auth-type veracode_hmac GET "https://api.veracode.com/appsec/v2/applications/${GUID}/findings?scan_type=STATIC&size=500&page=$i" > "$FINDINGS_TMP" 2>/dev/null
        
        debug_log "Merging page $((i-1)) into page $i"
        jq -s '.[0] as $f1 | .[1] as $f2 | ($f1 + $f2) | ._embedded.findings = ($f1._embedded.findings + $f2._embedded.findings)' \
            "$FINDINGS_PREV" "$FINDINGS_TMP" > "$FINDINGS_CURRENT"
    done
    
    # Rename final output
    mv "$TEMP_DIR/findings_p$((TOTAL_PAGES-1)).json" "$FINDINGS_OUTPUT_FILE"
fi

POLICY_FINDINGS_COUNT=$(jq '._embedded.findings | length' "$FINDINGS_OUTPUT_FILE")
debug_log "Total policy findings fetched: ${POLICY_FINDINGS_COUNT}"

if [ "$DEBUG_MODE" = true ]; then
    debug_log "Sample policy findings:"
    jq -r '._embedded.findings[0:3][] | "  issue_id=\(.issue_id), file=\(.finding_details.file_path), line=\(.finding_details.file_line_number), cwe=\(.finding_details.cwe.id), status=\(.finding_status.status), resolution=\(.finding_status.resolution)"' "$FINDINGS_OUTPUT_FILE" 2>/dev/null || true
fi

#############################################
# Filter Policy Findings Based on Filter Type
#############################################

EXCLUSION_CRITERIA_FILE="$TEMP_DIR/exclusion_criteria.txt"

debug_log "========================================"
debug_log "Filtering policy findings based on filter type: $FILTER_TYPE"

# Determine which policy findings to exclude from pipeline results
if [[ "$FILTER_TYPE" == *"mitigated"* ]]; then
    # For unmitigated filters, exclude only mitigated findings
    debug_log "Extracting mitigated findings (CLOSED + APPROVED + MITIGATED/POTENTIAL_FALSE_POSITIVE)"
    
    jq -r '._embedded.findings[] | select(
        .finding_status.status == "CLOSED" and
        .finding_status.resolution_status == "APPROVED" and
        (.finding_status.resolution == "MITIGATED" or .finding_status.resolution == "POTENTIAL_FALSE_POSITIVE") and
        .finding_details.file_path != null
    ) | "\(.finding_details.file_path)|\(.finding_details.cwe.id)|\(.finding_details.file_line_number)"' \
        "$FINDINGS_OUTPUT_FILE" > "$EXCLUSION_CRITERIA_FILE"
else
    # For new_findings or new_policy_violations, exclude ALL policy findings
    debug_log "Extracting all policy findings for exclusion"
    
    jq -r '._embedded.findings[] | select(
        .finding_details.file_path != null
    ) | "\(.finding_details.file_path)|\(.finding_details.cwe.id)|\(.finding_details.file_line_number)"' \
        "$FINDINGS_OUTPUT_FILE" > "$EXCLUSION_CRITERIA_FILE"
fi

EXCLUSION_COUNT=$(wc -l < "$EXCLUSION_CRITERIA_FILE" | tr -d ' ')
echo "Exclusion criteria count: ${EXCLUSION_COUNT}"

if [ "$EXCLUSION_COUNT" -eq 0 ]; then
    echo "No exclusions found."
    if [ "$INPUT_FILE" != "$OUTPUT_FILE" ]; then
        cp "$INPUT_FILE" "$OUTPUT_FILE"
    fi
    print_results "$PIPELINE_FINDINGS_COUNT" 0 "$PIPELINE_FINDINGS_COUNT"
    
    if [ "$PIPELINE_FINDINGS_COUNT" -gt 0 ] && [ "$FAIL_ON_POLICY" = true ]; then
        echo "Pipeline scan results contain policy violated findings."
        exit 1
    fi
    exit 0
fi

if [ "$DEBUG_MODE" = true ]; then
    debug_log "Exclusion criteria (first 5):"
    head -5 "$EXCLUSION_CRITERIA_FILE" | while read -r line; do
        debug_log "  $line"
    done
fi

#############################################
# Filter Pipeline Results
#############################################

echo "Filtering pipeline results with line number slop: ${LINE_NUMBER_SLOP}"
debug_log "Starting filtering process..."

# Create a temporary file for the filter script
FILTER_SCRIPT="$TEMP_DIR/filter.jq"

cat > "$FILTER_SCRIPT" << 'EOF'
# Input: exclusion array from stdin, slop from --argjson
# Parse exclusion criteria into map for faster lookup
($exclusions | map(split("|") | {
    file: (.[0] | if startswith("/") then .[1:] else . end),
    cwe: (.[1] | tonumber),
    line: (.[2] | tonumber)
}) ) as $exclusion_map |

# Filter findings
.findings |= map(
    . as $finding |
    
    # Check if this finding matches any exclusion criteria
    ($exclusion_map | any(
        .file == $finding.files.source_file.file and
        .cwe == ($finding.cwe_id | tonumber) and
        (($finding.files.source_file.line - .line) | fabs) <= $slop
    )) as $should_exclude |
    
    # Keep findings that should NOT be excluded
    select($should_exclude | not)
)
EOF

debug_log "Applying filter with jq..."

EXCLUSION_JSON=$(cat "$EXCLUSION_CRITERIA_FILE" | jq -R -s 'split("\n") | map(select(length > 0))')

jq --argjson exclusions "$EXCLUSION_JSON" \
   --argjson slop "$LINE_NUMBER_SLOP" \
   -f "$FILTER_SCRIPT" \
   "$INPUT_FILE" > "$OUTPUT_FILE"

FILTERED_COUNT=$(jq '.findings | length' "$OUTPUT_FILE")
REMOVED_COUNT=$((PIPELINE_FINDINGS_COUNT - FILTERED_COUNT))

echo "Results written to $OUTPUT_FILE"
debug_log "Output file size: $(wc -c < "$OUTPUT_FILE" | tr -d ' ') bytes"

print_results "$PIPELINE_FINDINGS_COUNT" "$EXCLUSION_COUNT" "$FILTERED_COUNT"

#############################################
# Exit Based on Results
#############################################

HAS_POLICY_VIOLATIONS=false
if [ "$FILTERED_COUNT" -gt 0 ]; then
    HAS_POLICY_VIOLATIONS=true
fi

echo "Has policy violated findings: ${HAS_POLICY_VIOLATIONS}"

if [ "$HAS_POLICY_VIOLATIONS" = true ] && [ "$FAIL_ON_POLICY" = true ]; then
    echo "Pipeline scan results contain policy violated findings."
    exit 1
fi

if [ "$FILTERED_COUNT" -eq 0 ]; then
    exit 0
else
    exit 0
fi
