#!/bin/bash
#
# run_all_scripts.sh
# Runs all Python scripts in ~/tools/scripts/ sequentially, once per invocation.
# Continues on failure. Logs output and a summary to ~/tools/scripts/logs/.
#

# ---- Config ----
SCRIPT_DIR="/home/admin/tools/scripts"
LOG_DIR="${SCRIPT_DIR}/logs"
PYTHON_BIN="/usr/bin/python3"
TIMEOUT_SECONDS=600   # Max runtime per script (10 minutes). Adjust as needed.

# ---- Setup ----
mkdir -p "${LOG_DIR}"
TIMESTAMP="$(date +'%Y-%m-%d_%H-%M-%S')"
RUN_LOG="${LOG_DIR}/run_${TIMESTAMP}.log"
SUMMARY_LOG="${LOG_DIR}/summary.log"

# Tee everything to the per-run log
exec > >(tee -a "${RUN_LOG}") 2>&1

echo "=========================================="
echo "Daily script run started: $(date)"
echo "Script directory: ${SCRIPT_DIR}"
echo "=========================================="

cd "${SCRIPT_DIR}" || { echo "ERROR: Cannot cd to ${SCRIPT_DIR}"; exit 1; }

# Counters
TOTAL=0
SUCCEEDED=0
FAILED=0
FAILED_SCRIPTS=()

# ---- Run each *.py file in sorted order ----
# Using shell glob; sort for deterministic order.
shopt -s nullglob
mapfile -t SCRIPTS < <(printf '%s\n' *.py | sort)
shopt -u nullglob

if [ "${#SCRIPTS[@]}" -eq 0 ]; then
    echo "No .py scripts found in ${SCRIPT_DIR}"
    exit 0
fi

for script in "${SCRIPTS[@]}"; do
    TOTAL=$((TOTAL + 1))
    echo ""
    echo "------------------------------------------"
    echo ">>> Running: ${script}   ($(date +'%H:%M:%S'))"
    echo "------------------------------------------"

    START_TS=$(date +%s)

    # Run with a timeout so a hung script can't block the rest.
    timeout "${TIMEOUT_SECONDS}" "${PYTHON_BIN}" "${script}"
    RC=$?

    END_TS=$(date +%s)
    DURATION=$((END_TS - START_TS))

    if [ "${RC}" -eq 0 ]; then
        echo "<<< OK: ${script} finished in ${DURATION}s"
        SUCCEEDED=$((SUCCEEDED + 1))
    elif [ "${RC}" -eq 124 ]; then
        echo "<<< TIMEOUT: ${script} exceeded ${TIMEOUT_SECONDS}s, killed."
        FAILED=$((FAILED + 1))
        FAILED_SCRIPTS+=("${script} (timeout)")
    else
        echo "<<< FAIL: ${script} exited with code ${RC} after ${DURATION}s"
        FAILED=$((FAILED + 1))
        FAILED_SCRIPTS+=("${script} (rc=${RC})")
    fi
done

# ---- Summary ----
echo ""
echo "=========================================="
echo "Run finished: $(date)"
echo "Total:     ${TOTAL}"
echo "Succeeded: ${SUCCEEDED}"
echo "Failed:    ${FAILED}"
if [ "${FAILED}" -gt 0 ]; then
    echo "Failed scripts:"
    for s in "${FAILED_SCRIPTS[@]}"; do
        echo "  - ${s}"
    done
fi
echo "Full log: ${RUN_LOG}"
echo "=========================================="

# Append a one-line summary to summary.log for quick scanning
echo "$(date +'%Y-%m-%d %H:%M:%S')  total=${TOTAL}  ok=${SUCCEEDED}  fail=${FAILED}  log=${RUN_LOG}" \
    >> "${SUMMARY_LOG}"

# ---- Log rotation: keep last 30 per-run logs ----
ls -1t "${LOG_DIR}"/run_*.log 2>/dev/null | tail -n +31 | xargs -r rm -f

# Exit 0 even if some scripts failed (we already logged them).
exit 0
