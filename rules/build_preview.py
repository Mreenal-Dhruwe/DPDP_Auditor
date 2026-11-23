"""Generate preview.html from dpdp_rules.yml. Usage: python build_preview.py dpdp_rules.yml preview.html"""
import sys, html, yaml
from collections import Counter

src, out = sys.argv[1], sys.argv[2]
raw = open(src, encoding="utf-8").read()
d = yaml.safe_load(raw)
rules, caps, meta = d["rules"], d["penalty_caps"], d["meta"]

ids = [r["id"] for r in rules]
assert len(ids) == len(set(ids)), "duplicate rule ids"
for r in rules:
    for k in ("id", "category", "title", "detects", "law", "penalty", "severity", "fix"):
        assert k in r, f"{r.get('id')} missing {k}"
    assert r["penalty"] in caps, f"{r['id']} unknown penalty {r['penalty']}"
    assert r["severity"] in d["severity_model"], f"{r['id']} bad severity"

e = html.escape
order = ["critical", "high", "medium", "low", "info"]
sev_count = Counter(r["severity"] for r in rules)
cats = list(dict.fromkeys(r["category"] for r in rules))

def card(r):
    cap = caps[r["penalty"]]
    refs = "".join(f'<span class="ref act">{e(a)}</span>' for a in r["law"]["act"]) + \
           "".join(f'<span class="ref rule">{e(x)}</span>' for x in r["law"]["rules"])
    det = "".join(f"<li>{e(x)}</li>" for x in r["detects"])
    tg = " ".join(f'<span class="tag">{e(t)}</span>' for t in r.get("targets", []))
    text = " ".join([r["id"], r["title"], r["category"], r["severity"], " ".join(r["law"]["act"]),
                     " ".join(r["law"]["rules"])]).lower()
    return f'''<article class="card" data-sev="{r['severity']}" data-cat="{e(r['category'])}" data-text="{e(text)}">
  <header><span class="sev s-{r['severity']}">{r['severity']}</span><code>{e(r['id'])}</code><span class="cat">{e(r['category'])}</span></header>
  <h3>{e(r['title'])}</h3>
  <div class="refs">{refs}</div>
  <p class="req">{e(r['law']['requirement'])}</p>
  <details><summary>Detects, severity &amp; fix</summary>
    <ul>{det}</ul>
    <p><b>Why {e(r['severity'])}:</b> {e(r.get('severity_reason',''))}</p>
    <p><b>Penalty cap:</b> {e(cap['cap'])} <span class="muted">(Schedule item {cap['schedule_item']}, {e(cap['provision'])})</span></p>
    <p><b>Fix:</b> {e(r['fix'])}</p>
    <p class="muted">Targets: {tg}</p>
  </details>
</article>'''

stats = "".join(f'<div class="stat"><span class="n s-{s}-t">{sev_count.get(s,0)}</span><span>{s}</span></div>' for s in order)
sev_btns = "".join(f'<button data-f="sev" data-v="{s}">{s}</button>' for s in order)
cat_opts = "".join(f'<option>{e(c)}</option>' for c in cats)
cards = "\n".join(card(r) for r in rules)

page = f'''<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>DPDP Rule Catalogue</title>
<style>
:root{{--bg:#0b1624;--panel:#12223a;--line:#21385a;--ink:#e6eef8;--mut:#8ea3bf;--teal:#2dd4bf;
--crit:#ef4444;--high:#f97316;--med:#eab308;--low:#38bdf8;--info:#94a3b8}}
*{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}}
.wrap{{max-width:1180px;margin:0 auto;padding:28px 20px 60px}}
h1{{margin:0;font-size:26px}} h1 span{{color:var(--teal)}} .sub{{color:var(--mut);margin:4px 0 20px}}
.stats{{display:grid;grid-template-columns:repeat(6,1fr);gap:10px;margin-bottom:18px}}
.stat{{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px;text-align:center;text-transform:capitalize;color:var(--mut);font-size:13px}}
.stat .n{{display:block;font-size:26px;font-weight:700;color:var(--ink)}}
.s-critical-t{{color:var(--crit)!important}}.s-high-t{{color:var(--high)!important}}.s-medium-t{{color:var(--med)!important}}.s-low-t{{color:var(--low)!important}}.s-info-t{{color:var(--info)!important}}
.tabs{{display:flex;gap:6px;margin-bottom:14px}} .tabs button{{background:none;border:1px solid var(--line);color:var(--mut);padding:7px 14px;border-radius:8px;cursor:pointer}}
.tabs button.on{{background:var(--teal);color:#06202a;border-color:var(--teal);font-weight:600}}
.bar{{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:16px}}
.bar input,.bar select{{background:var(--panel);color:var(--ink);border:1px solid var(--line);border-radius:8px;padding:8px 10px}}
.bar input{{flex:1;min-width:200px}} .bar button{{background:var(--panel);color:var(--mut);border:1px solid var(--line);border-radius:20px;padding:5px 12px;cursor:pointer;text-transform:capitalize}}
.bar button.on{{color:var(--ink);border-color:var(--teal)}}
.grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:14px}}
.card{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 16px}}
.card header{{display:flex;gap:8px;align-items:center;font-size:12px}} .card code{{color:var(--teal)}} .cat{{margin-left:auto;color:var(--mut)}}
.card h3{{margin:8px 0;font-size:16px}} .req{{color:var(--mut);font-size:13.5px;margin:6px 0}}
.sev{{text-transform:uppercase;font-weight:700;font-size:11px;padding:2px 8px;border-radius:5px;color:#111}}
.s-critical{{background:var(--crit);color:#fff}}.s-high{{background:var(--high)}}.s-medium{{background:var(--med)}}.s-low{{background:var(--low)}}.s-info{{background:var(--info)}}
.refs{{display:flex;flex-wrap:wrap;gap:5px}} .ref{{font-size:12px;padding:2px 7px;border-radius:5px;border:1px solid}}
.ref.act{{border-color:#3b82f6;color:#93c5fd}} .ref.rule{{border-color:var(--teal);color:var(--teal)}}
details{{margin-top:8px;font-size:13.5px}} summary{{cursor:pointer;color:var(--teal)}} details ul{{padding-left:18px;margin:6px 0}}
.muted{{color:var(--mut)}} .tag{{background:#1b3150;border-radius:4px;padding:1px 6px;font-size:11.5px}}
pre{{background:#07101c;border:1px solid var(--line);border-radius:10px;padding:16px;overflow:auto;font-size:13px;line-height:1.45;max-height:75vh}}
.k{{color:#7dd3fc}}.s{{color:#a7f3d0}}.c{{color:#64748b}}
.foot{{margin-top:26px;color:var(--mut);font-size:12.5px;border-top:1px solid var(--line);padding-top:12px}}
.hide{{display:none}} @media(max-width:700px){{.stats{{grid-template-columns:repeat(3,1fr)}}}}
</style></head><body><div class="wrap">
<h1>DPDP Compliance Auditor <span>· Rule Catalogue</span></h1>
<p class="sub">Hackasol 5.0 · CS-01 · v{e(meta['version'])} · {len(rules)} rules mapped to the DPDP Act 2023 and DPDP Rules 2025</p>
<div class="stats"><div class="stat"><span class="n">{len(rules)}</span><span>rules</span></div>{stats}</div>
<div class="tabs"><button class="on" data-tab="cards">Rule cards</button><button data-tab="yaml">Raw YAML</button></div>
<section id="cards">
<div class="bar"><input id="q" placeholder="Search id, title, section (e.g. 8(5), Rule 6)…">
<select id="cat"><option value="">All categories</option>{cat_opts}</select>{sev_btns}</div>
<div class="grid" id="grid">{cards}</div>
<p id="none" class="muted hide">No rules match.</p>
</section>
<section id="yaml" class="hide"><pre id="yml">{e(raw)}</pre></section>
<div class="foot">Sources: {e(meta['sources']['act'])}; {e(meta['sources']['rules'])}.<br>{e(meta['disclaimer'])}</div>
</div>
<script>
const cards=[...document.querySelectorAll('.card')],q=document.getElementById('q'),cat=document.getElementById('cat');let sev='';
function apply(){{const t=q.value.toLowerCase().trim();let n=0;cards.forEach(c=>{{const ok=(!t||c.dataset.text.includes(t))&&(!cat.value||c.dataset.cat===cat.value)&&(!sev||c.dataset.sev===sev);c.classList.toggle('hide',!ok);if(ok)n++}});document.getElementById('none').classList.toggle('hide',n>0)}}
q.oninput=apply;cat.onchange=apply;
document.querySelectorAll('[data-f=sev]').forEach(b=>b.onclick=()=>{{sev=sev===b.dataset.v?'':b.dataset.v;document.querySelectorAll('[data-f=sev]').forEach(x=>x.classList.toggle('on',x.dataset.v===sev));apply()}});
document.querySelectorAll('.tabs button').forEach(b=>b.onclick=()=>{{document.querySelectorAll('.tabs button').forEach(x=>x.classList.toggle('on',x===b));['cards','yaml'].forEach(id=>document.getElementById(id).classList.toggle('hide',id!==b.dataset.tab))}});
const p=document.getElementById('yml');p.innerHTML=p.innerHTML.split('\\n').map(l=>{{if(/^\\s*#/.test(l))return '<span class="c">'+l+'</span>';return l.replace(/^(\\s*-?\\s*)([\\w_]+)(:)/,'$1<span class="k">$2</span>$3').replace(/(&quot;[^&]*?&quot;)/g,'<span class="s">$1</span>')}}).join('\\n');
</script></body></html>'''
open(out, "w", encoding="utf-8").write(page)
print(f"OK: {len(rules)} rules, severities {dict(sev_count)}, categories {cats}")
