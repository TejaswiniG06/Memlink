"""Offline MemLink dashboard: one self-contained HTML file built from a verified run folder.

    python -B memlink_dashboard.py --run-output <run folder> --traces <phase1_traces.json> --output <dashboard.html>

* No network, no external scripts or fonts. Open the file in any browser.
* Priority (tier), conclusion (verdict) and review status are separate fields everywhere.
* Every drill-down excerpt is re-read from its source record at build time; every trace step must
  contain its quoted text or the build stops.
* The page embeds record excerpts: keep it local. Do not publish or commit it.
"""
import argparse
import html
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import memlink_adjudicate as adj
from memlink_assess import relocate

MAX_EXCERPT = 1400
SKIP_KEYS = {'Hexdump', 'Disasm', 'xml', '__children'}


def compact(value, depth=0):
    if isinstance(value, dict):
        return {k: compact(v, depth + 1) for k, v in value.items() if k not in SKIP_KEYS}
    if isinstance(value, list):
        return [compact(v, depth + 1) for v in value[:12]]
    if isinstance(value, str) and len(value) > 180:
        return value[:180] + '...'
    return value


def excerpt_text(text):
    try:
        parsed = json.loads(text)
        out = json.dumps(compact(parsed), indent=1, ensure_ascii=False)
    except json.JSONDecodeError:
        out = text.strip()
    return out if len(out) <= MAX_EXCERPT else out[:MAX_EXCERPT] + '\n...[truncated]'


def locator_for_ref(ref, root, maps):
    """Turn a rank-engine source reference (file#line=N | #flattened-row=N | #tid=N | #pid=N) into (file, locator)."""
    file, _, tail = str(ref).rpartition('#')
    key, _, value = tail.partition('=')
    if key == 'line':
        return file, {'line': int(value)}
    if key == 'flattened-row':
        return file, {'flat': int(value)}
    if key in ('tid', 'pid'):
        path = adj.translate(file, maps)
        path = path if path.is_absolute() else Path(root) / path
        rows = json.loads(path.read_text(encoding='utf-8-sig'))
        field = 'TID' if key == 'tid' else 'PID'
        for index, row in enumerate(rows):
            if str(row.get(field)) == value:
                return file, {'index': index}
    raise adj.RefError('cannot resolve reference %s' % ref)


def excerpt_for(file, locator, root, maps):
    text, layer = adj.record_text(file, locator, root, maps)
    return excerpt_text(text), layer


def build_data(run_output, traces_path, root, maps, yara_path=None):
    run_output = Path(run_output)
    yara = json.loads(Path(yara_path).read_text(encoding='utf-8')) if yara_path else None
    ranked = json.loads((run_output / 'ranking' / 'ranked_findings.json').read_text(encoding='utf-8'))
    results = {r['finding_id']: r for r in json.loads((run_output / 'adjudication' / 'adjudicated_findings.json').read_text(encoding='utf-8'))}
    report = json.loads((run_output / 'verification_report.json').read_text(encoding='utf-8'))
    ranking_meta = json.loads((run_output / 'ranking' / 'run_metadata.json').read_text(encoding='utf-8'))
    findings = []
    for position, row in enumerate(ranked, 1):
        result = results.get(row['finding_id'], {})
        observations = []
        for item in row['observation']:
            entry = {'text': item['text'], 'ref': item['ref'], 'family': item['family'], 'excerpt': None}
            try:
                file, locator = locator_for_ref(item['ref'], root, maps)
                entry['excerpt'], _ = excerpt_for(file, locator, root, maps)
            except (adj.RefError, OSError, ValueError, json.JSONDecodeError) as error:
                entry['excerpt_error'] = str(error)
            observations.append(entry)
        evidence = []
        for item in result.get('evidence_verified') or []:
            text, _ = excerpt_for(item['file'], item['locator'], root, maps)
            evidence.append({'id': item['id'], 'kind': item['kind'], 'layer': item['layer'], 'statement': item['statement'],
                             'file': item['file'], 'locator': item['locator'], 'excerpt': text})
        correlation = row['correlation']
        findings.append({
            'rank': position, 'id': row['finding_id'], 'action': row['action'], 'subject': row['subject'], 'tier': row['tier'],
            'verdict': result.get('verdict') or 'unassessed', 'confidence': result.get('confidence'),
            'evidence_strength': result.get('verified_evidence_strength'), 'review_status': result.get('status') or 'not_reviewed',
            'counted_with': result.get('counted_with'), 'groups': correlation['corroboration_groups'], 'identity': correlation['identity'],
            'temporal': correlation['temporal'], 'contradictions': correlation['contradictions'], 'links': correlation['links'],
            'predicates': row['predicates'], 'observations': observations, 'conclusion': result.get('conclusion'),
            'alternatives': result.get('alternatives_considered') or [], 'limitations': result.get('limitations'),
            'reason': result.get('reason'), 'would_resolve': result.get('would_resolve'), 'attack': result.get('attack') or [],
            'evidence': evidence, 'validation_errors': result.get('validation_errors') or [],
            'yara_rules': (yara or {}).get('per_finding', {}).get(row['finding_id'], [])})
    traces = []
    doc = json.loads(Path(traces_path).read_text(encoding='utf-8-sig'))
    for trace in doc['traces']:
        steps = []
        for step in trace['steps']:
            text, layer = adj.record_text(step['file'], step['locator'], root, maps)
            missing = [e for e in step['expect'] if str(e).casefold() not in text.casefold() and str(e).casefold().replace('\\', '\\\\') not in text.casefold()]
            if missing:
                raise SystemExit('trace %s step %r: record does not contain %r' % (trace['id'], step['label'], missing))
            if step.get('epoch') is not None:
                shown = datetime.fromtimestamp(step['epoch'], timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
                if shown != step['time']:
                    raise SystemExit('trace %s step %r: epoch %s is %s, not %s' % (trace['id'], step['label'], step['epoch'], shown, step['time']))
            steps.append({'time': step.get('time'), 'layer': step['layer'], 'label': step['label'], 'note': step['note'],
                          'file': step['file'], 'locator': step['locator'], 'excerpt': excerpt_text(text)})
        traces.append({'id': trace['id'], 'title': trace['title'], 'summary': trace['summary'],
                       'finding_subjects': trace.get('finding_subjects', []), 'steps': steps})
    meta = {'case': 'szechuan-case001', 'host': 'DC01 (CITADEL-DC01)', 'mode': report.get('mode'), 'frozen': report.get('frozen'),
            'spec_version': ranking_meta.get('specification_version'), 'spec_status': ranking_meta.get('specification_status'),
            'capture_utc': ranking_meta.get('memory_capture_utc'), 'run_utc': report.get('started_utc'),
            'overall': report.get('overall'), 'built_utc': datetime.now(timezone.utc).isoformat(timespec='seconds'),
            'not_evaluable': ranking_meta.get('actions_not_evaluable'),
            'groups_assumption': ranking_meta.get('relevant_groups_assumption')}
    if yara:
        meta['yara'] = yara['summary']
        meta['yara_unmatched'] = [{'pid': m['pid'], 'rule': m['rule'], 'address': m['address_hex'], 'vad': m['vad']}
                                  for m in yara['matches'] if m['verified'] and not m['candidate_finding']][:40]
    return {'meta': meta, 'findings': findings, 'traces': traces, 'checks': report.get('checks', [])}


def render(data):
    payload = json.dumps(data, ensure_ascii=False).replace('</', '<\\/')
    return TEMPLATE.replace('__DATA__', payload)


def main(argv=None):
    parser = argparse.ArgumentParser(description='Build the offline MemLink dashboard.')
    parser.add_argument('--run-output', required=True)
    parser.add_argument('--traces', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--root', default=str(Path.cwd()))
    parser.add_argument('--yara', help='yara_matches.json from memlink_yara.py (optional)')
    parser.add_argument('--path-map', action='append', default=[], metavar='SRC=DST')
    args = parser.parse_args(argv)
    maps = [tuple(item.split('=', 1)) for item in args.path_map]
    output = Path(args.output)
    if output.exists():
        print('refusing to overwrite %s' % output, file=sys.stderr)
        return 2
    data = build_data(args.run_output, args.traces, args.root, maps, args.yara)
    output.write_text(render(data), encoding='utf-8')
    print('dashboard written: %s (%d findings, %d traces, %.0f KB)' % (output, len(data['findings']), len(data['traces']), output.stat().st_size / 1024))
    return 0


TEMPLATE = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MemLink DC01 Review</title>
<style>
:root{--bg:#f6f7f9;--panel:#fff;--ink:#16202c;--mute:#5b6878;--line:#dfe3e9;--accent:#1f5fbf;
--t1:#b3261e;--t2:#b25e00;--t3:#5b6878;--mal:#b3261e;--ben:#1b7a43;--ind:#8a6d00;--ok:#1b7a43;--warn:#b25e00;--bad:#b3261e;
--chipbg:#eef1f5;--code:#f0f2f5;--sel:#e8f0fd}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#10151c;--panel:#18202a;--ink:#e6ebf1;--mute:#98a6b8;--line:#2a3441;--accent:#6aa3ff;
--t1:#ff8a80;--t2:#ffb74d;--t3:#98a6b8;--mal:#ff8a80;--ben:#6fd39a;--ind:#e6c35c;--ok:#6fd39a;--warn:#ffb74d;--bad:#ff8a80;--chipbg:#222c38;--code:#111820;--sel:#1e2c42}}
:root[data-theme="dark"]{--bg:#10151c;--panel:#18202a;--ink:#e6ebf1;--mute:#98a6b8;--line:#2a3441;--accent:#6aa3ff;--t1:#ff8a80;--t2:#ffb74d;--t3:#98a6b8;--mal:#ff8a80;--ben:#6fd39a;--ind:#e6c35c;--ok:#6fd39a;--warn:#ffb74d;--bad:#ff8a80;--chipbg:#222c38;--code:#111820;--sel:#1e2c42}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
header{padding:16px;border-bottom:1px solid var(--line);background:var(--panel)}
h1{margin:0 0 4px;font-size:20px}h2{font-size:16px;margin:20px 0 8px}h3{font-size:14px;margin:14px 0 6px;color:var(--mute);text-transform:uppercase;letter-spacing:.04em}
.sub{color:var(--mute);font-size:13px}
.sub,.banner{overflow-wrap:anywhere}
.banner{margin-top:10px;padding:8px 12px;border:1px solid var(--warn);border-left-width:4px;border-radius:6px;font-size:13px}
nav{display:flex;gap:4px;padding:8px 16px;border-bottom:1px solid var(--line);background:var(--panel);position:sticky;top:0;z-index:2;overflow-x:auto}
nav button{border:0;background:none;color:var(--mute);padding:8px 12px;border-radius:6px;font:inherit;cursor:pointer;white-space:nowrap}
nav button[aria-selected="true"]{background:var(--sel);color:var(--ink);font-weight:600}
button:focus-visible,tr:focus-visible,summary:focus-visible,input:focus-visible,select:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
main{padding:16px;max-width:1280px;margin:0 auto}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px}
.card .n{font-size:26px;font-weight:700}.card .l{color:var(--mute);font-size:12px}
table{border-collapse:collapse;width:100%;background:var(--panel)}th,td{padding:7px 9px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top;font-size:13px}
th{color:var(--mute);font-weight:600;position:sticky;top:0;background:var(--panel)}
tbody tr{cursor:pointer}tbody tr:hover{background:var(--sel)}tbody tr[aria-selected="true"]{background:var(--sel);box-shadow:inset 3px 0 0 var(--accent)}
.chip{display:inline-block;padding:1px 8px;border-radius:999px;background:var(--chipbg);font-size:12px;white-space:nowrap;border:1px solid var(--line)}
.t1{color:var(--t1);font-weight:700}.t2{color:var(--t2);font-weight:700}.t3{color:var(--t3);font-weight:600}
.v-malicious_supported{color:var(--mal);font-weight:700}.v-benign_supported{color:var(--ben);font-weight:700}.v-indeterminate{color:var(--ind);font-weight:700}.v-unassessed{color:var(--mute)}
.pass{color:var(--ok)}.warn{color:var(--warn)}.fail{color:var(--bad)}
.filters{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 10px}
input,select{background:var(--panel);color:var(--ink);border:1px solid var(--line);border-radius:6px;padding:6px 8px;font:inherit}
.split{display:grid;grid-template-columns:minmax(0,1.35fr) minmax(0,1fr);gap:14px;align-items:start}
@media (max-width:980px){.split{grid-template-columns:1fr}}
.tablewrap{max-height:70vh;overflow:auto;border:1px solid var(--line);border-radius:8px}
.detail{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:14px;max-height:78vh;overflow:auto;position:sticky;top:60px}
@media (max-width:980px){.detail{position:static;max-height:none}}
.trio{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin:8px 0}
@media (max-width:560px){.trio{grid-template-columns:1fr}}
.field{border:1px solid var(--line);border-radius:8px;padding:8px}.field .k{font-size:11px;color:var(--mute);text-transform:uppercase;letter-spacing:.05em}.field .v{font-size:15px;margin-top:2px}.field .s{font-size:12px;color:var(--mute)}
pre{margin:6px 0 0;padding:8px;background:var(--code);border-radius:6px;overflow:auto;font:12px/1.4 ui-monospace,Menlo,Consolas,monospace;white-space:pre-wrap;word-break:break-word}
details{margin:6px 0}summary{cursor:pointer;color:var(--accent)}
ul{margin:4px 0 4px 18px;padding:0}li{margin:3px 0}
.timeline{list-style:none;margin:0;padding:0;border-left:2px solid var(--line)}
.timeline li{position:relative;margin:0 0 12px 14px;padding:8px 10px;background:var(--panel);border:1px solid var(--line);border-radius:8px}
.timeline li::before{content:"";position:absolute;left:-22px;top:14px;width:10px;height:10px;border-radius:50%;background:var(--accent)}
.layer-disk::before{background:#7b61c9!important}.layer-eventlog::before{background:#d9822b!important}.layer-memory::before{background:#2a9d8f!important}
.time{font:12px ui-monospace,Menlo,Consolas,monospace;color:var(--mute)}
.muted{color:var(--mute)}.small{font-size:12px}
.pd{display:flex;gap:6px;flex-wrap:wrap;margin:4px 0}
</style>
</head>
<body>
<header>
<h1>MemLink: DC01 correlation review</h1>
<div class="sub" id="sub"></div>
<div class="banner" id="banner"></div>
</header>
<nav role="tablist" aria-label="Sections">
<button role="tab" aria-selected="true" data-tab="overview">Overview</button>
<button role="tab" aria-selected="false" data-tab="findings">Findings</button>
<button role="tab" aria-selected="false" data-tab="traces">Traces</button>
<button role="tab" aria-selected="false" data-tab="verify">Verification</button>
</nav>
<main>
<section id="overview"></section>
<section id="findings" hidden></section>
<section id="traces" hidden></section>
<section id="verify" hidden></section>
</main>
<script id="data" type="application/json">__DATA__</script>
<script>
"use strict";
const D = JSON.parse(document.getElementById('data').textContent);
const $ = (s, r=document) => r.querySelector(s);
function el(tag, props, ...kids){const e=document.createElement(tag);
  for(const [k,v] of Object.entries(props||{})){ if(k==='class')e.className=v; else if(k==='text')e.textContent=v; else if(k.startsWith('on'))e.addEventListener(k.slice(2),v); else if(v!==false&&v!==null&&v!==undefined)e.setAttribute(k,v);}
  for(const kid of kids.flat()){ if(kid===null||kid===undefined||kid===false)continue; e.append(kid.nodeType?kid:document.createTextNode(String(kid)));}
  return e;}
const VERDICT = {malicious_supported:'Malicious supported', benign_supported:'Benign supported', indeterminate:'Indeterminate', unassessed:'Unassessed'};
const REVIEW = {drafted_pending_user_confirmation:'Drafted, pending your confirmation', user_confirmed:'User confirmed', not_reviewed:'Not reviewed'};
const REVIEW_SHORT = {drafted_pending_user_confirmation:'Pending', user_confirmed:'Confirmed', not_reviewed:'Not reviewed'};
const TIER = {1:'Tier 1', 2:'Tier 2', 3:'Tier 3'};
const TIER_NOTE = {1:'Highest review priority', 2:'Predicate met, limited corroboration', 3:'Observation, no closed predicate met'};

$('#sub').textContent = `Case ${D.meta.case} · host ${D.meta.host} · recovered memory system time ${D.meta.capture_utc} · run ${D.meta.run_utc} · built ${D.meta.built_utc}`;
$('#banner').textContent = `Development run (not frozen) · specification ${D.meta.spec_version} (${D.meta.spec_status}) · retrospective evaluation of a known case · draft conclusions pending team review · this file embeds record excerpts: keep it local.`;

document.querySelectorAll('nav button').forEach(b=>b.addEventListener('click',()=>show(b.dataset.tab)));
function show(tab){document.querySelectorAll('nav button').forEach(b=>b.setAttribute('aria-selected',String(b.dataset.tab===tab)));
  ['overview','findings','traces','verify'].forEach(id=>{$('#'+id).hidden=(id!==tab);});}

function count(list, key){const m={};list.forEach(x=>{m[x[key]]=(m[x[key]]||0)+1});return m;}
function tierChip(t){return el('span',{class:'t'+t,text:TIER[t]});}
function verdictChip(v){return el('span',{class:'v-'+v,text:VERDICT[v]||v});}

function renderOverview(){
  const f=D.findings, uniq=f.filter(x=>!x.counted_with);
  const v=count(uniq,'verdict'), t=count(uniq,'tier'), merged=f.length-uniq.length;
  const root=$('#overview'); root.replaceChildren();
  root.append(el('h2',{text:'What the engine surfaced'}),
    el('div',{class:'cards'},
      card(f.length,'candidate findings ranked'), card(uniq.length,'findings after merging '+merged+' duplicate regions'),
      card(v.malicious_supported||0,'malicious supported'), card(v.benign_supported||0,'benign supported'), card(v.indeterminate||0,'indeterminate'),
      card(D.checks.filter(c=>c.status==='pass').length+'/'+D.checks.length,'verification checks passed')));
  root.append(el('h2',{text:'Priority and conclusion are separate'}),
    el('p',{class:'muted small',text:'Rows are review-priority tiers from the closed rule predicates. Columns are evidence-backed conclusions. A candidate can be low priority yet supported as malicious when convergent evidence goes beyond what a single predicate can express.'}));
  const verdicts=['malicious_supported','indeterminate','benign_supported'];
  const tb=el('table',{},el('thead',{},el('tr',{},el('th',{text:'Priority'}),...verdicts.map(x=>el('th',{text:VERDICT[x]})),el('th',{text:'Total'}))),
    el('tbody',{},...[1,2,3].map(tier=>el('tr',{},el('td',{},tierChip(tier),' ',el('span',{class:'muted small',text:TIER_NOTE[tier]})),
      ...verdicts.map(x=>{const n=uniq.filter(y=>y.tier===tier&&y.verdict===x).length;return el('td',{text:n||'·'});}),el('td',{text:t[tier]||0})))));
  root.append(el('p',{class:'muted small',text:'Counts exclude '+merged+' findings that describe the same injected regions as another finding; they stay listed under Findings.'}));
  root.append(el('div',{class:'tablewrap'},tb));
  root.append(el('h2',{text:'Supported malicious conclusions'}));
  const list=el('ul');
  f.filter(x=>x.verdict==='malicious_supported'&&!x.counted_with).forEach(x=>list.append(el('li',{},el('a',{href:'#',onclick:e=>{e.preventDefault();openFinding(x.id);}},x.subject),
    ' ',el('span',{class:'chip',text:x.action}),' ',tierChip(x.tier),' ',el('span',{class:'muted small',text:'confidence '+x.confidence}))));
  root.append(list);
  if(D.meta.yara){const y=D.meta.yara;
    root.append(el('h2',{text:'Signature corroboration (independent of the rule engine)'}),
      el('div',{class:'cards'},card(y.verified_matches,'verified YARA matches'),card(y.processes_with_matches.length,'processes with matches'),
        card(y.a03_candidates_with_signature+'/'+y.a03_candidates,'injection candidates with a signature hit'),card(y.matches_outside_any_candidate_region,'matches outside any candidate region')),
      el('p',{class:'muted small',text:y.note}),
      el('p',{class:'small',text:'Rules hit: '+Object.entries(y.rules_hit).map(([r,n])=>r+' ('+n+')').join(', ')}));
    if((D.meta.yara_unmatched||[]).length)root.append(el('details',{},el('summary',{text:'Matches not tied to a behavioral candidate ('+D.meta.yara_unmatched.length+' shown)'}),
      el('ul',{class:'small'},...D.meta.yara_unmatched.map(m=>el('li',{text:'PID '+m.pid+' · '+m.rule+' · '+m.address+(m.vad?' · '+m.vad.protection+(m.vad.private?' private':' file-backed'):'')})))));}
  root.append(el('h2',{text:'What is not evaluated'}),
    el('p',{class:'muted small',text:Object.entries(D.meta.not_evaluable||{}).map(([a,w])=>a+': '+w).join(' | ')}));
}
function card(n,l){return el('div',{class:'card'},el('div',{class:'n',text:n}),el('div',{class:'l',text:l}));}

let selected=null;
function renderFindings(){
  const root=$('#findings'); root.replaceChildren();
  const q=el('input',{type:'search',placeholder:'Search subject or text',id:'q','aria-label':'Search findings'});
  const mk=(id,label,opts)=>el('select',{id,'aria-label':label},el('option',{value:'',text:label+': all'}),...opts.map(o=>el('option',{value:o[0],text:o[1]})));
  const fv=mk('fv','Conclusion',Object.entries(VERDICT).filter(([k])=>k!=='unassessed')), ft=mk('ft','Priority',[[1,'Tier 1'],[2,'Tier 2'],[3,'Tier 3']]),
        fa=mk('fa','Action',[...new Set(D.findings.map(x=>x.action))].sort().map(a=>[a,a]));
  const body=el('tbody');
  const table=el('table',{},el('thead',{},el('tr',{},...['#','Action','Subject','Priority','Conclusion','Review status'].map(h=>el('th',{text:h})))),body);
  const detail=el('div',{class:'detail',id:'detail','aria-live':'polite'},el('p',{class:'muted',text:'Select a finding to see its observations, correlation, predicates, conclusion and source records.'}));
  root.append(el('div',{class:'filters'},q,fv,ft,fa,el('span',{class:'muted small',id:'shown'})),el('div',{class:'split'},el('div',{class:'tablewrap'},table),detail));
  function draw(){const s=q.value.toLowerCase();let n=0;body.replaceChildren();
    D.findings.forEach(x=>{
      if(fv.value&&x.verdict!==fv.value)return; if(ft.value&&String(x.tier)!==ft.value)return; if(fa.value&&x.action!==fa.value)return;
      if(s&&!(x.subject+' '+(x.conclusion||'')).toLowerCase().includes(s))return; n++;
      const tr=el('tr',{tabindex:'0','data-id':x.id,'aria-selected':String(selected===x.id)},
        el('td',{text:x.rank}),el('td',{text:x.action}),el('td',{text:x.subject}),el('td',{},tierChip(x.tier)),el('td',{},verdictChip(x.verdict),x.counted_with?el('span',{class:'muted small',text:' (with another finding)'}):null),
        el('td',{},el('span',{class:'chip',title:REVIEW[x.review_status]||x.review_status,text:REVIEW_SHORT[x.review_status]||x.review_status})));
      tr.addEventListener('click',()=>openFinding(x.id)); tr.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();openFinding(x.id);}});
      body.append(tr);});
    $('#shown').textContent=n+' of '+D.findings.length+' shown';}
  [q,fv,ft,fa].forEach(c=>c.addEventListener('input',draw)); draw();
}
function field(k,v,s){return el('div',{class:'field'},el('div',{class:'k',text:k}),el('div',{class:'v'},v),s?el('div',{class:'s',text:s}):null);}
function excerptBox(label,ref,text){return el('details',{},el('summary',{text:label}),el('div',{class:'small muted',text:ref}),el('pre',{text:text||'(no excerpt available)'}));}
function refText(file,loc){return file+' @ '+Object.entries(loc).map(([k,v])=>k+' '+v).join(', ');}
function openFinding(id){
  selected=id; show('findings'); if(!$('#detail')) renderFindings();
  document.querySelectorAll('#findings tbody tr').forEach(r=>r.setAttribute('aria-selected',String(r.dataset.id===id)));
  const x=D.findings.find(f=>f.id===id); const d=$('#detail'); d.replaceChildren();
  d.append(el('h2',{text:x.subject,style:'margin-top:0'}),el('div',{class:'muted small',text:x.id+' · action '+x.action+' · rank '+x.rank}));
  d.append(el('div',{class:'trio'},
    field('Priority',tierChip(x.tier),TIER_NOTE[x.tier]+'. Review priority only; not a verdict.'),
    field('Conclusion',verdictChip(x.verdict),(x.confidence?'confidence '+x.confidence+' · ':'')+'verified evidence '+(x.evidence_strength||'none')),
    field('Review status',el('span',{text:REVIEW[x.review_status]||x.review_status}),x.review_status==='user_confirmed'?'':'Not yet confirmed by you; excluded from any freeze.')));
  if(x.counted_with)d.append(el('p',{class:'small muted',text:'Counted once together with finding '+x.counted_with+' (same underlying injected region).'}));
  d.append(el('h3',{text:'Conclusion'}),el('p',{text:x.conclusion||'No adjudication entry.'}));
  if(x.verdict==='indeterminate')d.append(el('p',{class:'small'},el('b',{text:'Why undecided: '}),x.reason||'',' ',el('b',{text:'Would resolve: '}),x.would_resolve||''));
  if(x.attack.length)d.append(el('div',{class:'pd'},...x.attack.map(a=>el('span',{class:'chip',text:'ATT&CK '+a.technique+' (supported by '+a.supported_by.join(', ')+')'}))));
  if(x.alternatives.length)d.append(el('h3',{text:'Alternatives considered'}),el('ul',{},...x.alternatives.map(a=>el('li',{},el('b',{text:a.alternative+': '}),a.disposition))));
  if(x.limitations)d.append(el('h3',{text:'Limitations'}),el('p',{class:'small',text:x.limitations}));
  d.append(el('h3',{text:'Correlation'}),
    el('p',{class:'small',text:'Identity: '+x.identity+' · temporal: '+x.temporal+' · corroboration groups ('+x.groups.length+'): '+(x.groups.join(', ')||'none')+(x.contradictions.length?' · contradictions: '+x.contradictions.join(', '):'')}));
  if(x.links.length)d.append(el('ul',{class:'small'},...x.links.map(l=>el('li',{text:l.method+' ('+l.strength+'): '+l.from+' to '+l.to+(l.detail?' - '+l.detail:'')}))));
  if(D.meta.yara)d.append(el('h3',{text:'Signature corroboration (independent; not used in tier or conclusion)'}),
    el('p',{class:'small',text:x.yara_rules.length?('YARA rules matched inside this finding\'s region: '+x.yara_rules.join(', ')):'No YARA match inside this finding\'s region.'}));
  d.append(el('h3',{text:'Closed predicates (rule engine)'}),
    el('ul',{class:'small'},...Object.entries(x.predicates).map(([k,v])=>el('li',{},el('span',{class:v.satisfied?'pass':'muted',text:(v.satisfied?'met ':'not met ')}),k+' - '+v.basis))));
  d.append(el('h3',{text:'Observations and source records'}));
  x.observations.forEach(o=>d.append(el('div',{},el('div',{class:'small',text:o.text}),excerptBox('Source record',o.ref,o.excerpt||o.excerpt_error))));
  if(x.evidence.length){d.append(el('h3',{text:'Evidence cited by the conclusion (re-verified)'}));
    x.evidence.forEach(e=>d.append(el('div',{},el('div',{class:'small'},el('span',{class:'chip',text:e.kind+' · '+e.layer}),' '+e.statement),excerptBox('Cited record',refText(e.file,e.locator),e.excerpt))));}
  d.scrollTop=0;
}

function renderTraces(){
  const root=$('#traces'); root.replaceChildren();
  root.append(el('p',{class:'muted small',text:'Each step is re-read from its source record when the dashboard is built; the build stops if a record does not contain the quoted text. Undated steps are corroboration with no timestamp in the record.'}));
  D.traces.forEach(t=>{
    const dated=t.steps.filter(s=>s.time).sort((a,b)=>a.time.localeCompare(b.time)), undated=t.steps.filter(s=>!s.time);
    const link=D.findings.find(f=>t.finding_subjects.includes(f.subject));
    root.append(el('h2',{text:t.title}),el('p',{text:t.summary}),
      link?el('p',{class:'small'},'Finding: ',el('a',{href:'#',onclick:e=>{e.preventDefault();openFinding(link.id);}},link.subject),' ',tierChip(link.tier),' ',verdictChip(link.verdict)):null);
    root.append(el('ul',{class:'timeline'},...dated.map(s=>step(s))));
    if(undated.length)root.append(el('h3',{text:'Corroboration without a timestamp'}),el('ul',{class:'timeline'},...undated.map(s=>step(s))));
  });
}
function step(s){return el('li',{class:'layer-'+s.layer},el('div',{class:'time',text:(s.time||'no timestamp')+' · '+s.layer}),el('div',{},el('b',{text:s.label})),el('div',{class:'small muted',text:s.note}),excerptBox('Source record',refText(s.file,s.locator),s.excerpt));}

function renderVerify(){
  const root=$('#verify'); root.replaceChildren();
  root.append(el('h2',{text:'Run verification (fails closed before any result is written)'}));
  root.append(el('div',{class:'tablewrap'},el('table',{},el('thead',{},el('tr',{},el('th',{text:'Check'}),el('th',{text:'Result'}),el('th',{text:'Detail'}))),
    el('tbody',{},...D.checks.map(c=>el('tr',{style:'cursor:default'},el('td',{text:c.check}),el('td',{},el('span',{class:c.status,text:c.status.toUpperCase()})),
      el('td',{},el('pre',{text:typeof c.detail==='string'?c.detail:JSON.stringify(c.detail,null,1),style:'margin:0'}))))))));
  root.append(el('h2',{text:'Assumptions awaiting your decision'}),
    el('p',{class:'small muted',text:'Relevant corroboration groups per action (not defined by the spec): '+JSON.stringify(D.meta.groups_assumption)}));
}
renderOverview(); renderFindings(); renderTraces(); renderVerify();
</script>
</body>
</html>
'''

if __name__ == '__main__':
    sys.exit(main())
