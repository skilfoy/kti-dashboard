# Builds lib/triage-gold.json, the analyst-labelled set the machine triage tier is scored against: one row per evidence
# item with its title, theater and intrusion vector (null when the analyst assigned none). The file ships with the
# service and is pushed to the collector's bucket as ref/triage-gold.json (/api/admin?op=push&asset=gold).
import hashlib, json, os, sys
root = sys.argv[1] if len(sys.argv) > 1 else '.'
items = json.load(open(os.path.join(root, 'data/authored/items.json')))
vectors = [v['vector'] for v in json.load(open(os.path.join(root, 'data/authored/vectors.json')))]
def vec(name):
    if not name: return None
    hit = [v for v in vectors if v == name or v.startswith(name + ' ')]
    if len(hit) != 1: raise SystemExit(f'item vector {name!r} matches {len(hit)} catalog vectors')
    return hit[0]
rows = [{'id': i['item_id'], 'title': i['title'], 'theater': i['theater_id'], 'vector': vec(i.get('vector'))} for i in items if i.get('title') and i.get('theater_id')]
body = json.dumps(rows, ensure_ascii=False, sort_keys=True, separators=(',', ':'))
out = {'sha': hashlib.sha256(body.encode()).hexdigest()[:16], 'built_from': 'data/authored/items.json', 'items': rows}
path = os.path.join(root, 'lib/triage-gold.json')
text = json.dumps(out, ensure_ascii=False, separators=(',', ':')) + '\n'
if '--check' in sys.argv:
    if not os.path.exists(path) or open(path, encoding='utf-8').read() != text: raise SystemExit('lib/triage-gold.json is out of date: run python3 pipeline/triage_gold.py')
    print(f'OK triage gold: {len(rows)} items, sha {out["sha"]}')
else:
    open(path, 'w', encoding='utf-8').write(text); print(f'wrote {path}: {len(rows)} items, sha {out["sha"]}')
