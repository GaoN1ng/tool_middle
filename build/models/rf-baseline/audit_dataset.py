"""Audit offline ELF alignment and shared ancestry before learning."""
import hashlib
import json
from pathlib import Path
from collections import Counter
from elftools.elf.elffile import ELFFile
from dataset import OUT


def allocated(path):
    with path.open('rb') as stream:
        elf = ELFFile(stream)
        return {(s['sh_addr'], s['sh_size']): hashlib.sha256(s.data()).hexdigest()
                for s in elf.iter_sections() if s['sh_flags'] & 2 and s['sh_type'] != 'SHT_NOBITS'}


def main():
    checks = []; counts = Counter(); positive_groups = {}
    for line in (OUT / 'development-functions.jsonl').open():
        r = json.loads(line)
        if r['kind'] == 'executable':
            p = Path(r['absolute_path'])
            sibling = next((p.parent / n for n in ['inspection.so', 'unstripped.so', 'symbolic.so']
                            if (p.parent / n).exists()), None)
            ok = sibling is not None and allocated(p) == allocated(sibling)
            checks.append({'id': r['id'], 'sibling': str(sibling), 'allocated_bytes_match': ok})
            if not ok and any(f['annotation']['algorithms'] for f in r['functions']):
                raise ValueError('Unverified binary annotations: ' + r['id'])
        for f in r['functions']:
            counts[f['annotation']['role']] += 1
            for a in f['annotation']['algorithms']:
                positive_groups.setdefault(a, set()).add(r['group'])
    report = {'binary_checks': checks, 'role_counts': dict(counts),
              'algorithm_groups': {a: sorted(g) for a, g in positive_groups.items()},
              'learning_group_corrections': {'libecc-generic': 'libecc'},
              'policy': 'Inference never reads symbols; only annotation sibling allocated bytes verified here.'}
    (OUT / 'annotation-audit.json').write_text(json.dumps(report, indent=2) + '\n')
    print({a: len(g) for a, g in positive_groups.items()}, flush=True)


if __name__ == '__main__': main()
