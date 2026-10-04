#!/bin/bash
BASE="$HOME/Downloads/anonymous-india-method-lab/http-method-lab"

if [ ! -d "$BASE/tutorial" ] || [ ! -d "$BASE/challenge" ]; then
    echo "[!] Missing tutorial/ or challenge/ under $BASE"
    exit 1
fi

# Kill stale servers
pkill -f "$BASE/tutorial/app.py" 2>/dev/null
pkill -f "$BASE/challenge/app.py" 2>/dev/null
sleep 0.5

echo "[*] Starting tutorial lab on http://0.0.0.0:5000"
cd "$BASE/tutorial"
python3 app.py >/tmp/tutorial.log 2>&1 &
TUT_PID=$!

echo "[*] Starting challenge lab on http://0.0.0.0:5001"
cd "$BASE/challenge"
python3 app.py >/tmp/challenge.log 2>&1 &
CHAL_PID=$!

sleep 1.5

echo
echo "  Tutorial : http://$(hostname -I | awk '{print $1}'):5000"
echo "  Challenge: http://$(hostname -I | awk '{print $1}'):5001"
echo "  Logs     : /tmp/tutorial.log  /tmp/challenge.log"
echo
echo "Press Ctrl+C to stop both."

trap "kill $TUT_PID $CHAL_PID 2>/dev/null; exit 0" INT TERM
wait
