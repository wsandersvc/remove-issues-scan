#!/bin/bash

# Enhanced Policy Results Filter Script
#
# This script filters Veracode Policy Scan results
#
# Dependencies: httpie, jq, curl
# Best suited for veracode/api-signing container or systems with httpie installed

set -e

#############################################
# Configuration and Defaults
#############################################

DEFAULT_FILTER="all_results"
DEBUG_MODE=false
FAIL_ON_POLICY=false

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
  --output-file <file>             Output file name

Optional arguments:
  --filter <type>                  Filter type (default: "all_results")
  --input-file <file>              Input policy results file (default: fetch from API)
  --fail-on-policy                 Exit with error code if policy violations found
  --debug                          Enable debug logging

Available filter options:
  all_results                      All findings
  policy_violations                Only policy violating findings
  unmitigated_results              Exclude mitigated findings
  unmitigated_policy_violations    Unmitigated policy violations only
  new_findings                     New findings only
  new_policy_violations            New policy violations only
  open_findings                    Open findings only
  closed_findings                  Closed findings only

Examples:
  # Fetch from API and filter
  $0 "MyApp" --filter unmitigated_results --output-file out.json

  # Use local file
  $0 "MyApp" --input-file policy_flaws.json --output-file filtered.json

Environment Variables:
  VERACODE_API_KEY_ID              <vid>
  VERACODE_API_KEY_SECRET          <vkey>

EOF
}

print_results() {
    echo "=============================================="
    echo "Total findings: $1"
    echo "Removed findings: $3"
    echo "Filtered findings: $2"
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
INPUT_FILE=""
OUTPUT_FILE=""

# Validate required arguments
if [ -z "$VERACODE_API_KEY_ID" ] || [ -z "$VERACODE_API_KEY_SECRET" ] || [ -z "$APP_NAME" ]; then
    echo "Error: vid, vkey, and appname are required"
    print_usage
    exit 1
fi

while [ $# -gt 0 ]; do
    case "$1" in
        --filter) FILTER_TYPE="$2"; shift 2 ;;
        --input-file) INPUT_FILE="$2"; shift 2 ;;
        --output-file) OUTPUT_FILE="$2"; shift 2 ;;
        --fail-on-policy) FAIL_ON_POLICY=true; shift ;;
        --debug) DEBUG_MODE=true; shift ;;
        --help|-h) print_usage; exit 0 ;;
        *) echo "Unknown argument: $1"; print_usage; exit 1 ;;
    esac
done

# Validate file args
if [ -n "$INPUT_FILE" ] && [ -z "$OUTPUT_FILE" ]; then
    echo "Error: --output-file required when --input-file provided"
    exit 1
fi
if [ -z "$INPUT_FILE" ] && [ -z "$OUTPUT_FILE" ]; then
    echo "Error: --output-file required when fetching from API"
    exit 1
fi
if [ -n "$INPUT_FILE" ] && [ ! -f "$INPUT_FILE" ]; then
    echo "Error: Input file '$INPUT_FILE' not found"
    exit 1
fi

###############################################################################
# Display Configuration
###############################################################################

echo "############################################"
echo "Configuration:"
echo "  Application: $APP_NAME"
echo "  Input file: ${INPUT_FILE:-"(fetch from API)"}"
echo "  Output file: $OUTPUT_FILE"
echo "  Filter type: $FILTER_TYPE"
echo "  Fail on policy: $FAIL_ON_POLICY"
echo "  Debug mode: $DEBUG_MODE"
echo "############################################"
echo ""

debug_log "VERACODE_API_KEY_ID (masked): ${VERACODE_API_KEY_ID:0:8}..."

###############################################################################
# Setup TEMP Directory
###############################################################################

TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

###############################################################################
# Fetch or Read Policy Findings
###############################################################################

FINDINGS_FILE=""

if [ -n "$INPUT_FILE" ]; then
    # Use local file
    debug_log "Using local file: $INPUT_FILE"
    FINDINGS_FILE="$INPUT_FILE"
else
    # Fetch from API
    echo "Fetching findings from Veracode API..."
    
    # Fetch GUID by application name
    debug_log "Fetching application GUID for: $APP_NAME"
    APP_RESPONSE="$TEMP_DIR/app.json"
    
    http --auth-type veracode_hmac GET \
        "https://api.veracode.com/appsec/v1/applications?name=$(printf %s "$APP_NAME" | jq -sRr @uri)" \
        > "$APP_RESPONSE" 2>/dev/null || {
        echo "Error: Failed to fetch application"
        exit 1
    }
    
    GUID=$(jq -r '._embedded.applications[0].guid // empty' "$APP_RESPONSE")
    [ -z "$GUID" ] && { echo "Error: Application '$APP_NAME' not found"; exit 1; }
    echo "Application GUID: ${GUID}"
    
    # Fetch findings with pagination
    FINDINGS_FILE="$TEMP_DIR/findings.json"
    PAGE=0
    
    # Fetch first page
    debug_log "Fetching page 0..."
    http --auth-type veracode_hmac GET \
        "https://api.veracode.com/appsec/v2/applications/${GUID}/findings?scan_type=STATIC&page=${PAGE}" \
        > "$TEMP_DIR/page_${PAGE}.json" 2>/dev/null || {
        echo "Error: Failed to fetch findings"
        exit 1
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
fi

###############################################################################
# Count Total Findings
###############################################################################

TOTAL_FINDINGS=$(jq '._embedded.findings | length' "$FINDINGS_FILE" 2>/dev/null || echo "0")
if [ -z "$TOTAL_FINDINGS" ] || [ "$TOTAL_FINDINGS" = "null" ]; then
    echo "Error: Could not parse findings file"
    exit 1
fi
echo "Total findings in input: ${TOTAL_FINDINGS}"

# Debug: Show sample findings
if [ "$DEBUG_MODE" = true ] && [ "$TOTAL_FINDINGS" -gt 0 ]; then
    debug_log "Sample findings:"
    jq -r '._embedded.findings[0:3][] | 
        "  id=\(.issue_id) file=\(.finding_details.file_path) line=\(.finding_details.file_line_number) cwe=\(.finding_details.cwe.id) status=\(.finding_status.status)"' \
        "$FINDINGS_FILE" 2>/dev/null || true
fi

###############################################################################
# Apply Filter
###############################################################################

debug_log "Applying filter: $FILTER_TYPE"
FILTERED_FILE="$TEMP_DIR/filtered.json"

case "$FILTER_TYPE" in
    all_results)
        # No filtering - copy as-is
        debug_log "No filtering applied"
        cp "$FINDINGS_FILE" "$FILTERED_FILE"
        ;;
    
    policy_violations)
        # Keep only policy violating findings
        debug_log "Keeping only policy violations"
        jq '._embedded.findings |= map(select(.violates_policy == true))' \
            "$FINDINGS_FILE" > "$FILTERED_FILE"
        ;;
    
    unmitigated_results)
        # Exclude mitigated findings (CLOSED + APPROVED + MITIGATED/POTENTIAL_FALSE_POSITIVE)
        # Using De Morgan's law: NOT (A AND B AND C) = (NOT A) OR (NOT B) OR (NOT C)
        debug_log "Excluding mitigated findings"
        jq '._embedded.findings |= map(select(
            .finding_status.status != "CLOSED" or
            .finding_status.resolution_status != "APPROVED" or
            (.finding_status.resolution != "MITIGATED" and 
             .finding_status.resolution != "POTENTIAL_FALSE_POSITIVE")
        ))' "$FINDINGS_FILE" > "$FILTERED_FILE"
        ;;
    
    unmitigated_policy_violations)
        # Keep policy violations that are NOT mitigated
        # Using De Morgan's law for negation
        debug_log "Keeping unmitigated policy violations"
        jq '._embedded.findings |= map(select(
            .violates_policy == true and
            (
                .finding_status.status != "CLOSED" or
                .finding_status.resolution_status != "APPROVED" or
                (.finding_status.resolution != "MITIGATED" and 
                 .finding_status.resolution != "POTENTIAL_FALSE_POSITIVE")
            )
        ))' "$FINDINGS_FILE" > "$FILTERED_FILE"
        ;;
    
    new_findings)
        # Keep only findings marked as new
        debug_log "Keeping only new findings"
        jq '._embedded.findings |= map(select(.finding_status.new == true))' \
            "$FINDINGS_FILE" > "$FILTERED_FILE"
        ;;
    
    new_policy_violations)
        # Keep only new findings that violate policy
        debug_log "Keeping only new policy violations"
        jq '._embedded.findings |= map(select(
            .violates_policy == true and
            .finding_status.new == true
        ))' "$FINDINGS_FILE" > "$FILTERED_FILE"
        ;;
    
    open_findings)
        # Keep only open findings
        debug_log "Keeping only open findings"
        jq '._embedded.findings |= map(select(.finding_status.status == "OPEN"))' \
            "$FINDINGS_FILE" > "$FILTERED_FILE"
        ;;
    
    closed_findings)
        # Keep only closed findings
        debug_log "Keeping only closed findings"
        jq '._embedded.findings |= map(select(.finding_status.status == "CLOSED"))' \
            "$FINDINGS_FILE" > "$FILTERED_FILE"
        ;;
    
    *)
        echo "Error: Unknown filter type '$FILTER_TYPE'"
        print_usage
        exit 1
        ;;
esac

###############################################################################
# Count and Write Results
###############################################################################

FILTERED_COUNT=$(jq '._embedded.findings | length' "$FILTERED_FILE" 2>/dev/null || echo "0")
REMOVED_COUNT=$((TOTAL_FINDINGS - FILTERED_COUNT))

debug_log "Filtered: ${FILTERED_COUNT}, Removed: ${REMOVED_COUNT}"

# Write output
cp "$FILTERED_FILE" "$OUTPUT_FILE"
echo ""
echo "Results written to $OUTPUT_FILE"
print_results "$TOTAL_FINDINGS" "$FILTERED_COUNT" "$REMOVED_COUNT"

###############################################################################
# Exit Based on Results
###############################################################################

# Check if any filtered findings violate policy
HAS_POLICY_VIOLATIONS=false
if [ "$FILTERED_COUNT" -gt 0 ]; then
    POLICY_VIOLATION_COUNT=$(jq '[._embedded.findings[] | select(.violates_policy == true)] | length' \
        "$OUTPUT_FILE" 2>/dev/null || echo "0")
    [ "$POLICY_VIOLATION_COUNT" -gt 0 ] && HAS_POLICY_VIOLATIONS=true
fi

echo "Has policy violated findings: ${HAS_POLICY_VIOLATIONS}"

# Exit with error if policy violations found and --fail-on-policy is set
if [ "$HAS_POLICY_VIOLATIONS" = true ] && [ "$FAIL_ON_POLICY" = true ]; then
    echo "Filtered results contain policy violated findings."
    exit 1
fi

if [ "$FILTERED_COUNT" -eq 0 ]; then
    echo "No findings after filtering."
fi
exit 0
