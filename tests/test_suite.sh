#!/usr/bin/env bash
set -u

BIN="irondome"
LOG_FILE="/var/log/irondome/irondome.log"
PID_FILE="/run/irondome.pid"
TEST_DIR_A="/tmp/irondome_eval_a"
TEST_DIR_B="/tmp/irondome_eval_b"

RED='\033[0;31m'
GRN='\033[0;32m'
CYA='\033[0;36m'
YLW='\033[1;33m'
NC='\033[0m'

PASSED=0
FAILED=0

pass() {
    echo -e "  ${GRN}[PASS]${NC} $1"
    PASSED=$((PASSED + 1))
}

fail() {
    echo -e "  ${RED}[FAIL]${NC} $1"
    FAILED=$((FAILED + 1))
    echo "========= LOG ==========="
    tail "$LOG_FILE"
    echo "========================="
}

cleanup() {
    if [[ -f "$PID_FILE" ]]; then
        local pid
        pid=$(cat "$PID_FILE" 2>/dev/null || true)
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid" 2>/dev/null || true
            sleep 0.5
        fi
    fi
    pkill -x irondome 2>/dev/null || true
    rm -rf "$TEST_DIR_A" "$TEST_DIR_B"
}

trap cleanup EXIT

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Error: Run the evaluation test suite as root (sudo ./tests/test_suite.sh)${NC}"
    exit 1
fi

echo -e "${CYA}====================================================${NC}"
echo -e "${CYA}         Iron Dome Evaluation Test Suite            ${NC}"
echo -e "${CYA}====================================================${NC}"

cleanup
rm -f "$LOG_FILE"
mkdir -p "$TEST_DIR_A" "$TEST_DIR_B"

# Seed baseline low-entropy files before starting daemon
for i in {1..80}; do
    python3 -c 'print("Plaintext baseline evaluation content for Iron Dome.\n" * 400)' \
        > "$TEST_DIR_A/doc_$i.txt"
done
for i in {1..10}; do
    python3 -c 'print("Sensitive configuration record = 1234567890\n" * 500)' \
        > "$TEST_DIR_B/config_$i.conf"
done

# Test Root Requirement
echo -e "\n${YLW}[1/7] Checking root privilege enforcement...${NC}"
if sudo -u nobody "$BIN" "$TEST_DIR_A" 2>/dev/null; then
    fail "Daemon allowed execution as non-root user 'nobody'"
else
    pass "Daemon rejected non-root execution"
fi

# Test Daemonization, Multi-path CLI & Singleton Lock
echo -e "\n${YLW}[2/7] Checking daemonization, PID lock, and multi-path monitoring...${NC}"
"$BIN" "$TEST_DIR_A" "$TEST_DIR_B"
sleep 1

if [[ -f "$PID_FILE" ]]; then
    DAEMON_PID=$(cat "$PID_FILE")
    if [[ -n "$DAEMON_PID" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        PPID_VAL=$(ps -o ppid= -p "$DAEMON_PID" | tr -d ' ')
        pass "Daemon running in background (PID: $DAEMON_PID, PPID: $PPID_VAL)"
    else
        fail "PID file exists ($PID_FILE) but process is not running"
        exit 1
    fi
else
    fail "PID file $PID_FILE was not created"
    exit 1
fi

if "$BIN" "$TEST_DIR_A" 2>/dev/null; then
    fail "Second daemon instance was allowed to start simultaneously"
else
    pass "Singleton flock() prevented duplicate daemon instance"
fi

# Test File Entropy Change Detection
echo -e "\n${YLW}[3/7] Triggering file entropy change in $TEST_DIR_A...${NC}"
dd if=/dev/urandom of="$TEST_DIR_A/doc_1.txt" bs=64K count=4 status=none
sleep 1

if grep -q "\[ALERT\] \[ENTROPY\]" "$LOG_FILE"; then
    pass "Entropy change detected and logged to $LOG_FILE"
else
    fail "No [ALERT] [ENTROPY] entry found in $LOG_FILE"
fi

# Test Intensive Cryptographic Activity Detection
echo -e "\n${YLW}[4/7] Triggering cryptographic activity (OpenSSL AES-256-CBC) in $TEST_DIR_B...${NC}"
for i in {1..5}; do
    openssl enc -aes-256-cbc -pbkdf2 -pass pass:supersecret \
        -in "$TEST_DIR_B/config_$i.conf" \
        -out "$TEST_DIR_B/config_$i.conf.enc" 2>/dev/null
    mv "$TEST_DIR_B/config_$i.conf.enc" "$TEST_DIR_B/config_$i.conf"
done
sleep 1

if grep -q "\[ALERT\] \[CRYPTO_ACTIVITY\]" "$LOG_FILE"; then
    pass "Cryptographic activity detected and logged to $LOG_FILE"
else
    fail "No [ALERT] [CRYPTO_ACTIVITY] entry found in $LOG_FILE"
fi

# Test Disk Read Abuse Detection
echo -e "\n${YLW}[5/7] Triggering disk read abuse in $TEST_DIR_A...${NC}"
python3 - << 'EOF'
import glob
files = glob.glob("/tmp/irondome_eval_a/doc_*.txt")
for _ in range(25):
    for f in files:
        with open(f, "rb") as fp:
            _ = fp.read()
EOF
sleep 1

if grep -q "\[ALERT\] \[DISK_READ_ABUSE\]" "$LOG_FILE"; then
    pass "Disk read abuse detected and logged to $LOG_FILE"
else
    fail "No [ALERT] [DISK_READ_ABUSE] entry found in $LOG_FILE"
fi

# Test Dynamic Subdirectory Creation
echo -e "\n${YLW}[6/7] Checking dynamic subdirectory watch (FAN_ONDIR)...${NC}"
BEFORE_ENT_COUNT=$(grep -c "\[ALERT\] \[ENTROPY\]" "$LOG_FILE" || true)
mkdir -p "$TEST_DIR_A/newly_created_subdir"
sleep 0.5
dd if=/dev/urandom of="$TEST_DIR_A/newly_created_subdir/ransom.enc" bs=64K count=2 status=none
sleep 1
AFTER_ENT_COUNT=$(grep -c "\[ALERT\] \[ENTROPY\]" "$LOG_FILE" || true)

if [[ "$AFTER_ENT_COUNT" -gt "$BEFORE_ENT_COUNT" ]]; then
    pass "Newly created subdirectory automatically watched and alerted"
else
    fail "Did not detect high-entropy file inside newly created subdirectory"
fi

# Test Memory Limit (< 100 MB) and Daemon Stability
echo -e "\n${YLW}[7/7] Verifying memory ceiling (< 100 MB) and daemon stability...${NC}"
if kill -0 "$DAEMON_PID" 2>/dev/null; then
    RSS_KB=$(awk '/VmRSS:/ {print $2}' "/proc/$DAEMON_PID/status")
    RSS_MB=$(awk "BEGIN {printf \"%.2f\", $RSS_KB / 1024}")
    if [[ "$RSS_KB" -lt 102400 ]]; then
        pass "Daemon alive and memory usage within limit: ${RSS_MB} MB (${RSS_KB} kB < 102400 kB)"
    else
        fail "Daemon exceeded 100 MB memory limit: ${RSS_MB} MB (${RSS_KB} kB)"
    fi
else
    fail "Daemon crashed unexpectedly during stress tests"
fi

# Test bonus Incremental Backups
echo -e "\n${YLW}[Bonus] Verifying incremental backups in HOME directory...${NC}"
USER_HOME=$(getent passwd "${SUDO_USER:-root}" | cut -d: -f6)
BACKUP_DIR="$USER_HOME/irondome_backups"

echo "Incremental backup test payload" > "$TEST_DIR_A/bonus_incremental.txt"
sleep 3

if [[ -L "$BACKUP_DIR/latest" ]] && find "$BACKUP_DIR/latest" -name "bonus_incremental.txt" | grep -q "bonus_incremental.txt"; then
    SNAP_COUNT=$(find "$BACKUP_DIR" -maxdepth 1 -type d -name "snapshot_*" | wc -l)
    pass "Incremental backup verified in $BACKUP_DIR ($SNAP_COUNT snapshots created)"
else
    fail "Incremental backup file 'bonus_incremental.txt' not found in $BACKUP_DIR/latest"
fi

echo -e "\n${CYA}--- Sample Alerts from $LOG_FILE ---${NC}"
grep "\[ALERT\]" "$LOG_FILE" | tail -n 8 || true

echo -e "\n${CYA}====================================================${NC}"
echo -e "Results: ${GRN}${PASSED} passed${NC}, ${RED}${FAILED} failed${NC}"
echo -e "${CYA}====================================================${NC}"

[[ "$FAILED" -eq 0 ]]
