# WPForms ≤ 2.0.2.1 — Bypass of the CVE-2026-88996 Fix (Unauthenticated Reflected XSS)

**Affected:** WPForms – AI Form Builder for WordPress (free/lite), version 2.0.2.1 — the
current latest at time of disclosure (also the version that *contains* the fix for
CVE-2026-88996). The Pro edition shares the Smart Tag renderer.
**Class:** Unauthenticated reflected cross-site scripting (CWE-79) with verified JavaScript
execution, via incomplete fix of CVE-2026-88996 / GHSA-8j5g-9vmv-9mmw.
**Discovered:** 2026-09-27 · **Reported to Patchstack:** 2026-09-27 · **Declined:**
2026-09-28 ("the issue only appears when the site administrator has written a bare Smart
Tag where an HTML attribute name belongs... not a default setup or a pattern anyone would
realistically author" — technical validity not disputed) · **Public:** 2026-09-28.

## Summary

The 2.0.2.1 fix for CVE-2026-93485-family reflected XSS escapes Smart Tag values that are
substituted into markup (`SmartTags::escape_for_attribute()` encodes quotes and
whitespace). That is effective whenever the substituted value lands inside a **quoted
attribute value**. When a form author places a bare Smart Tag at an **attribute-name
position** in the Confirmation message — e.g.:

```html
<input {field_id="3"}>
```

a submitted field value containing no quotes and no whitespace, such as
`onmouseover=alert(1)`, is inserted **verbatim** and becomes a new, live event-handler
attribute. The escaping never encodes `=`, and attribute names require neither quotes nor
whitespace. The confirmation returned to the anonymous submitter then contains:

```html
<input onmouseover=alert(1)>
```

Anonymous submissions to `admin-ajax.php` (`action=wpforms_submit`,
`wp_ajax_nopriv_*`) are nonce-free by design for logged-out users, so this is a fully
unauthenticated reflected XSS. Arbitrary JavaScript executes within the single-token
constraint via `onmouseover=eval(String.fromCharCode(...))`.

## The delta that proves it is a fix gap

On the same form, the parent-CVE payload shape — quote-breaking from inside a quoted
value, e.g. `x" onfocus=alert(1) autofocus y="` — is correctly escaped at **every**
position (`&quot;` / `&#32;` encoding observed). The 2.0.2.1 escaping works everywhere
except attribute-name placement. This is an incomplete fix of the same substitution
sink, not a separate feature gap.

## Reproducing

```bash
# 1. WordPress + WPForms lite 2.0.2.1, create a form with a single-line text field (id 3)
# 2. Set the form's Confirmation message to:
#      A: <input value="{field_id="3"}">  B: <input {field_id="3"}>
# 3. Run the PoC (stdlib-only Python 3):
python3 poc.py --url http://target.example/form-page/
```

Expected output:

```
[+] field 3 reflects into the confirmation message
[payload (bypass position)] occurrences: LIVE=1 ESCAPED/INERT=2
    LIVE  -> ...<input onmouseover=alert(poc93485)>...
[control] parent-CVE payload escaped everywhere: YES (fix works at value positions)
=== VERDICT: VULNERABLE — payload reaches attribute-NAME position unescaped ===
```

`poc.py` auto-discovers the form, fields, and reflecting field; submits anonymously; and
classifies every occurrence as LIVE (attribute-name injection) vs ESCAPED (quoted-value,
the parent-CVE shape). Exit code 0 = vulnerable.

## Preconditions (stated honestly)

The form's admin-authored Confirmation message must contain a bare input-reflecting Smart
Tag inside markup at attribute-name position. Patchstack's researchers assessed this as
an unrealistic authoring pattern; it is nonetheless a documented feature position, the
escaping exists precisely to make markup-context substitution safe, and the author
receives no error — only silent injection.

## Suggested fix

Encode `=` in the markup-context escaping, or contextually parse the confirmation markup
and permit Smart Tag substitution only in text and quoted-attribute-value positions.

## Files

- `poc.py` — self-contained PoC (no server-side steps, no dependencies)
- `poc.sh` — curl-based minimal variant

## Disclaimer

For authorized testing and educational purposes only. The reporter publishes this after
a coordinated-submission attempt was declined; the technical finding was not disputed.
