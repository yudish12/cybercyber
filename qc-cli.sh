#!/bin/bash
set -uo pipefail

BASE_URL="${CYBER_QC_BASE_URL:-https://cyber-qc-web-24635836730.us-central1.run.app}"
MODE="pre"
TASK_ID=""
ZIPS=()

usage() {
  echo "usage: cli.sh <task.zip-or-folder> [<task2.zip-or-folder> ...] [--mode pre|post] [--task-id ID]" >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="${2:-}"; shift 2 ;;
    --task-id) TASK_ID="${2:-}"; shift 2 ;;
    -h|--help) usage ;;
    *) ZIPS+=("$1"); shift ;;
  esac
done

[[ ${#ZIPS[@]} -gt 0 ]] || usage
[[ "$MODE" == "pre" || "$MODE" == "post" ]] || { echo "error: --mode must be 'pre' or 'post'" >&2; exit 1; }

check_one() {
  local input="$1"
  local zip="$input"
  local tmp_archive=""
  trap '[[ -n "$tmp_archive" ]] && rm -f "$tmp_archive"' RETURN

  if [[ -d "$input" ]]; then
    local dir_name
    dir_name="$(basename "$(cd "$input" && pwd)")"
    tmp_archive="$(mktemp -t "cyberqc-XXXXXX").tar.gz"
    echo "[$dir_name] archiving folder..." >&2
    tar -czf "$tmp_archive" -C "$(dirname "$(cd "$input" && pwd)")" "$dir_name" \
      || { echo "[$dir_name] error: failed to archive folder" >&2; return 1; }
    zip="$tmp_archive"
  elif [[ ! -f "$input" ]]; then
    echo "error: not a file or folder: $input" >&2
    return 1
  fi

  local archive_name out_file upload_resp upload_url object_name body
  if [[ -n "$tmp_archive" ]]; then
    archive_name="$(basename "$input").tar.gz"
  else
    archive_name="$(basename "$zip")"
  fi

  echo "[$archive_name] requesting upload URL..." >&2
  upload_resp="$(curl -fsS -X POST "$BASE_URL/api/gcs-upload-url" \
    -H "content-type: application/json" \
    -d "{\"filename\":\"$archive_name\"}")" || { echo "[$archive_name] error: could not get an upload URL" >&2; return 1; }

  upload_url="$(echo "$upload_resp" | grep -o '"uploadUrl":"[^"]*"' | sed 's/"uploadUrl":"//;s/"$//')"
  object_name="$(echo "$upload_resp" | grep -o '"objectName":"[^"]*"' | sed 's/"objectName":"//;s/"$//')"

  if [[ -z "$upload_url" || -z "$object_name" ]]; then
    echo "[$archive_name] error: did not get an upload URL back: $upload_resp" >&2
    return 1
  fi

  echo "[$archive_name] uploading..." >&2
  curl -fsS -X PUT "$upload_url" -H "content-type: application/octet-stream" --data-binary "@$zip" -o /dev/null \
    || { echo "[$archive_name] error: upload failed" >&2; return 1; }

  echo "[$archive_name] running quality check (mode=$MODE)..." >&2
  out_file="${archive_name%.tar.gz}"
  out_file="${out_file%.*}-qc-report-${MODE}.md"
  body="$(curl -sS -X POST "$BASE_URL/api/check-gcs?format=md" \
    -H "content-type: application/json" \
    -d "{\"objectName\":\"$object_name\",\"mode\":\"$MODE\",\"archiveName\":\"$archive_name\",\"taskId\":\"$TASK_ID\"}")"

  if [[ "$body" != "# Deep Hack Project Quality Check Report"* ]]; then
    echo "[$archive_name] error running quality check:" >&2
    echo "$body" >&2
    return 1
  fi

  printf '%s\n' "$body" > "$out_file"
  echo "[$archive_name] report saved to $out_file"
}

fail_count=0
for zip in "${ZIPS[@]}"; do
  check_one "$zip" || fail_count=$((fail_count + 1))
done

echo "Done: $((${#ZIPS[@]} - fail_count))/${#ZIPS[@]} succeeded" >&2
[[ "$fail_count" -eq 0 ]]
