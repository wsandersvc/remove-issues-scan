#!/bin/bash

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
DEFAULT_OUTPUT_FILE="filtered-results.json"
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
Usage: $0 <appname> [options]

Required arguments:
  appname                          Veracode application name

Optional arguments:
  --line-number-slop <n>           Line number slop for matching (default: 3)
  --filter <type>                  Filter type (default: "all_results")
  --input-file <file>              Input pipeline results file (default: "results.json")
  --output-file <file>             Output file (default: "filtered-results.json")
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
  $0 "MyApp" --filter unmitigated_results --input-file results.json
  $0 "MyApp" --filter policy_violations --debug
  $0 "MyApp" --line-number-slop 5 --fail-on-policy

Environment Variables:
  VERACODE_API_KEY_ID              <vid>
  VERACODE_API_KEY_SECRET          <vkey>
EOF
}

print_results() {    
    echo "=============================================="
    echo "Total findings: $1"
    echo "Removed findings: $2"
    echo "Filtered findings: $3"
    echo "=============================================="
}

#############################################
# Parse Command Line Arguments
#############################################

if [ $# -eq 0 ]; then
    print_usage
    exit 1
fi

APP_NAME="${1}"
shift 1 2>/dev/null || true

# Parse optional arguments
INPUT_FILE="$DEFAULT_INPUT_FILE"
OUTPUT_FILE="$DEFAULT_OUTPUT_FILE"

# Validate required arguments
if [ -z "$VERACODE_API_KEY_ID" ] || [ -z "$VERACODE_API_KEY_SECRET" ] || [ -z "$APP_NAME" ]; then
    echo "Error: vid, vkey, and appname are required"
    print_usage
    exit 1
fi

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

# Validate input file exists
if [ ! -f "$INPUT_FILE" ]; then
    echo "Error: Input file '$INPUT_FILE' not found"
    exit 1
fi

# Set output file to input file if not specified (overwrite mode)
if [ -z "$OUTPUT_FILE" ]; then
    OUTPUT_FILE="$INPUT_FILE"
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
   [ "$FILTER_TYPE" = "all_results" ]; then
    
    debug_log "========================================"
    debug_log "Skipping Veracode API calls - early exit condition met"
    debug_log "  Reason: Filter '$FILTER_TYPE' does not require Veracode API calls"
    debug_log "  - Pipeline findings count: $PIPELINE_FINDINGS_COUNT"
    debug_log "  - Filter type: $FILTER_TYPE"
    debug_log ""
    debug_log "NOTE: To fetch and filter against Veracode platform findings, use:"
    debug_log "  - policy_violations"
    debug_log "  - unmitigated_results"
    debug_log "  - unmitigated_policy_violations"
    # debug_log "  - new_findings"
    # debug_log "  - new_policy_violations"
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

# Fetch from API
echo "Fetching findings from Veracode API..."

# Fetch findings with pagination
FINDINGS_FILE="$TEMP_DIR/findings.json"
PAGE=0

# Fetch first page
debug_log "Fetching page 0..."
http --auth-type veracode_hmac GET \
    "https://api.veracode.com/appsec/v2/applications/${GUID}/findings?scan_type=STATIC&page=${PAGE}" \
    > "$TEMP_DIR/page_${PAGE}.json" 2>/dev/null || {
    echo "Error: Failed to fetch findings"
    cp "$INPUT_FILE" "$OUTPUT_FILE"
    print_results "$PIPELINE_FINDINGS_COUNT" 0 "$PIPELINE_FINDINGS_COUNT"
    exit 0
}

TOTAL_PAGES=$(jq -r '.page.total_pages // 1' "$TEMP_DIR/page_0.json")
TOTAL_ELEMENTS=$(jq -r '.page.total_elements // 0' "$TEMP_DIR/page_0.json")
echo "Fetched page 1 of ${TOTAL_PAGES} (${TOTAL_ELEMENTS} total findings)"

# Fetch remaining pages
if [ "$TOTAL_PAGES" -gt 1 ]; then
    for PAGE in $(seq 1 $((TOTAL_PAGES-1))); do
        echo "Fetching page $((PAGE+1)) of ${TOTAL_PAGES}..."
        http --auth-type veracode_hmac GET \
            "https://api.veracode.com/appsec/v2/applications/${GUID}/findings?scan_type=STATIC&page=${PAGE}" \
            > "$TEMP_DIR/page_${PAGE}.json" 2>/dev/null || {
            echo "Warning: Failed to fetch page $PAGE"
            break
        }
    done
    
    # Merge all pages
    debug_log "Merging ${TOTAL_PAGES} pages..."
    jq -s 'reduce .[] as $page ({"_embedded": {"findings": []}, "_links": .[0]._links, "page": .[0].page}; 
        ._embedded.findings += $page._embedded.findings)' \
        "$TEMP_DIR"/page_*.json > "$FINDINGS_FILE"
else
    mv "$TEMP_DIR/page_0.json" "$FINDINGS_FILE"
fi

echo "Successfully fetched all findings"

POLICY_FINDINGS_COUNT=$(jq '._embedded.findings | length' "$FINDINGS_FILE")
debug_log "Total policy findings fetched: ${POLICY_FINDINGS_COUNT}"

if [ "$DEBUG_MODE" = true ]; then
    debug_log "Sample policy findings:"
    jq -r '._embedded.findings[0:3][] | "  issue_id=\(.issue_id), file=\(.finding_details.file_path), line=\(.finding_details.file_line_number), cwe=\(.finding_details.cwe.id), status=\(.finding_status.status), resolution=\(.finding_status.resolution)"' "$FINDINGS_FILE" 2>/dev/null || true
fi

#############################################
# Filter Policy Findings Based on Filter Type
#########################################

EXCLUSION_CRITERIA_FILE="$TEMP_DIR/exclusion_criteria.txt"

debug_log "========================================"
debug_log "Filtering policy findings based on filter type: $FILTER_TYPE"

case "$FILTER_TYPE" in
    policy_violations)
        debug_log "Policy violations"
        jq -r '._embedded.findings[] | select(
            .violates_policy == true and 
            .finding_details.file_path != null
        ) | "\(.finding_details.file_path)|\(.finding_details.cwe.id)|\(.finding_details.file_line_number)"' \
            "$FINDINGS_FILE" > "$EXCLUSION_CRITERIA_FILE"
        ;;
    unmitigated_results)
        debug_log "Unmitigated findings"
        jq -r '._embedded.findings[] | select(
            .finding_status.status != "CLOSED" or
            .finding_status.resolution_status != "APPROVED" or
            (.finding_status.resolution != "MITIGATED" and
             .finding_status.resolution != "POTENTIAL_FALSE_POSITIVE") and 
             .finding_details.file_path != null
        ) | "\(.finding_details.file_path)|\(.finding_details.cwe.id)|\(.finding_details.file_line_number)"' \
            "$FINDINGS_FILE" > "$EXCLUSION_CRITERIA_FILE"
        ;;
    unmitigated_policy_violations)
        debug_log "Unmitigated policy violations"
        jq -r '._embedded.findings[] | select(
            .violates_policy == true and
            (
                .finding_status.status != "CLOSED" or
                .finding_status.resolution_status != "APPROVED" or
                (.finding_status.resolution != "MITIGATED" and
                .finding_status.resolution != "POTENTIAL_FALSE_POSITIVE")
            ) and 
            .finding_details.file_path != null
        ) | "\(.finding_details.file_path)|\(.finding_details.cwe.id)|\(.finding_details.file_line_number)"' \
            "$FINDINGS_FILE" > "$EXCLUSION_CRITERIA_FILE"
        ;;
    new_findings)
        debug_log "New findings"
        jq -r '._embedded.findings[] | select(
            .finding_status.new == true and
            .finding_details.file_path != null
        ) | "\(.finding_details.file_path)|\(.finding_details.cwe.id)|\(.finding_details.file_line_number)"' \
            "$FINDINGS_FILE" > "$EXCLUSION_CRITERIA_FILE"
        ;;
    new_policy_violations)
        debug_log "New policy violations"
        jq -r '._embedded.findings[] | select(
            .finding_status.new == true and 
            .violates_policy == true and 
            .finding_details.file_path != null
        ) | "\(.finding_details.file_path)|\(.finding_details.cwe.id)|\(.finding_details.file_line_number)"' \
            "$FINDINGS_FILE" > "$EXCLUSION_CRITERIA_FILE"
        ;;
    *)
        echo "Error: Unknown filter type '$FILTER_TYPE'"
        print_usage
        exit 1
        ;;
esac

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
    select($should_exclude)
)
EOF

debug_log "Applying filter with jq..."

EXCLUSION_JSON=$(cat "$EXCLUSION_CRITERIA_FILE" | jq -R -s 'split("\n") | map(select(length > 0))')

###############################################################################
# Count and Write Results
###############################################################################

jq --argjson exclusions "$EXCLUSION_JSON" \
   --argjson slop "$LINE_NUMBER_SLOP" \
   -f "$FILTER_SCRIPT" \
   "$INPUT_FILE" > "$OUTPUT_FILE"

FILTERED_COUNT=$(jq '.findings | length' "$OUTPUT_FILE" 2>/dev/null || echo "0")
REMOVED_COUNT=$((PIPELINE_FINDINGS_COUNT - EXCLUSION_COUNT))

debug_log "Filtered: ${FILTERED_COUNT}, Removed: ${REMOVED_COUNT}"

echo ""
echo "Results written to $OUTPUT_FILE"
print_results "$PIPELINE_FINDINGS_COUNT" "$REMOVED_COUNT" "$FILTERED_COUNT"
debug_log "Output file size: $(wc -c < "$OUTPUT_FILE" | tr -d ' ') bytes"

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
