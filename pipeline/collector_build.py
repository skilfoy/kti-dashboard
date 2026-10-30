# Joins threat-feeds/neon/parts/*.mjs (in lib/collector.js PARTS order) into threat-feeds/neon/collector.mjs, the build
# the tests import and whose SHA-256 goes into the Neon function's TI_CODE_SHA256. Prints per-file SHA-1 for Vercel.
import hashlib, os, re, sys
root = sys.argv[1] if len(sys.argv) > 1 else 'threat-feeds'
parts = re.search(r"PARTS = \[([^\]]+)\]", open(os.path.join(root, 'lib/collector.js')).read()).group(1)
names = [p.strip().strip("'") for p in parts.split(',')]
src = b''.join(open(os.path.join(root, 'neon/parts', n), 'rb').read() for n in names)
open(os.path.join(root, 'neon/collector.mjs'), 'wb').write(src)
for n in names:
    b = open(os.path.join(root, 'neon/parts', n), 'rb').read()
    print(f'neon/parts/{n} {hashlib.sha1(b).hexdigest()} {len(b)}')
print('collector.mjs sha256', hashlib.sha256(src).hexdigest(), len(src))
