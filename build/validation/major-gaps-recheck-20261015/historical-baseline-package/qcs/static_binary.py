"""Known static math primitives with complete callee-binding verification.

Reference bodies come only from development builds. A masked CALL displacement
never trusts an arbitrary replacement target: the entire reachable local graph
must match, including recursive edges and immutable data. This recovers primitive
semantics for surrounding unseen callers; it is not generic limb inference.
"""
import hashlib
import json
import time
from pathlib import Path
from functools import lru_cache
from .function_signatures import anchor,valid_literals

DATABASE = Path(__file__).parent / 'rules/static_primitives.json'


@lru_cache(maxsize=2)
def database(path,digest):
    import yara
    db=json.loads(Path(path).read_text());rules={}
    for domain in {s['architecture'] for s in db['signatures']}:
        # Five-byte tail thunks have only an opcode after relocation masking.
        # Resolve them at actual call targets, never search all file bytes for
        # one-byte candidates. They can never introduce a semantic root.
        selected=[(i,s) for i,s in enumerate(db['signatures'])
                  if s['architecture']==domain and s['significant_bits']>=16]
        if selected:rules[domain]=yara.compile(source='\n'.join(
            f'rule sig_{i} {{ strings: $body = {{ {anchor(s)[1]} }} condition: $body }}' for i,s in selected))
    return db,rules


def targets(regions, domain, deadline, *, path=None, diagnostics=None):
    if not DATABASE.exists():
        return {}, []
    db, rules = database(str(DATABASE), hashlib.sha256(DATABASE.read_bytes()).hexdigest())
    if domain not in rules:
        return {}, []
    from .guomi.binary_semantics import decode, disassembler
    from .guomi.binary_bignum import PointerLift,import_slots
    resolver=PointerLift(domain,regions,import_slots(path)) if path is not None else None
    candidates = {};steps=0
    for base, _, data, flags in regions:
        if not flags & 1:
            continue
        if time.monotonic() > deadline:
            raise ValueError('Static primitive graph budget exhausted')
        for match in rules[domain].match(data=data, timeout=max(1, int(deadline-time.monotonic()))):
            sig = db['signatures'][int(match.rule.split('_')[1])]
            body_bytes = bytes.fromhex(sig['bytes']);mask = bytes.fromhex(sig['mask'])
            shift, _ = anchor(sig)
            for string in match.strings:
                for instance in string.instances:
                    steps+=1
                    if steps%128==0 and time.monotonic()>deadline:raise ValueError('Static primitive candidate budget exhausted')
                    at = instance.offset-shift
                    if at < 0 or at+len(mask) > len(data):
                        continue
                    body = data[at:at+len(mask)]
                    if any((b&m) != expected for b, m, expected in zip(body, mask, body_bytes)):
                        continue
                    address = base+at
                    if valid_literals(sig, body, address, regions):
                        candidates[(address, sig['id'])] = (sig, body)
    by_id={s['id']:s for s in db['signatures'] if s['architecture']==domain}
    queue=list(candidates)
    for address,identity in queue:
        sig,body=candidates[address,identity]
        for call in sig.get('calls',[]):
            tiny=by_id.get(call.get('signature'))
            if tiny is None or tiny['significant_bits']>=16:continue
            if tiny.get('semantic') or tiny['bytes']!='e900000000' or tiny['mask']!='ff00000000':continue
            ins=next(decode(disassembler(domain),body[call['offset']:],address+call['offset']),None)
            if ins is None or not ins.operands or ins.operands[-1].type!=2:continue
            dest=ins.operands[-1].imm;key=(dest,tiny['id'])
            if key in candidates:continue
            raw=next((data[dest-base:dest-base+5] for base,_,data,flags in regions if flags&1 and base<=dest and dest+5<=base+len(data)),None)
            if raw and raw[0]==0xe9:
                candidates[key]=(tiny,raw);queue.append(key)
        if len(queue)>50000 or time.monotonic()>deadline:raise ValueError('Static primitive dependency budget exhausted')
    valid = set(candidates)
    dependencies = {}
    invalid_calls=[]
    for key, (sig, body) in candidates.items():
        if time.monotonic()>deadline:raise ValueError('Static primitive graph budget exhausted')
        address, _ = key;links=[];ok=True
        for call in sig.get('calls', []):
            instruction = next(decode(disassembler(domain), body[call['offset']:], address+call['offset']), None)
            if call.get('pointer')=='x86_rip':
                if instruction is None or instruction.mnemonic!='lea' or len(instruction.operands)!=2 or instruction.operands[1].type!=3:
                    ok=False;break
                mem=instruction.operands[1].mem
                if instruction.reg_name(mem.base)!='rip':ok=False;break
                dest=instruction.address+instruction.size+mem.disp
                target=(dest,call['signature'])
                if target not in candidates:ok=False;break
                links.append(target);continue
            if instruction is None or not instruction.operands or instruction.operands[-1].type != 2:
                ok=False;break
            dest=instruction.operands[-1].imm
            if domain=='thumb':dest&=~1
            if 'external' in call:
                if resolver is None or resolver.target(instruction)!=call['external']:
                    ok=False;break
                continue
            target=(dest,call['signature'])
            if target not in candidates:
                invalid_calls.append({'function':sig.get('function'),'call_offset':call['offset'],
                                      'destination':dest,'expected':call['signature']})
                ok=False;break
            links.append(target)
        if not ok:valid.discard(key)
        dependencies[key]=links
    # Greatest fixed point permits genuine recursive primitive call graphs;
    # an altered/missing callee invalidates every dependent root.
    changed=True
    while changed:
        changed=False
        for key in list(valid):
            if any(dep not in valid for dep in dependencies[key]):
                valid.remove(key);changed=True
    meanings={};witnesses=[]
    if diagnostics is not None:
        diagnostics.update(matched_bodies=len(candidates),valid_graph_nodes=len(valid),invalid_calls=invalid_calls,
                           candidates=[{'address':a,'id':i,'function':s['function']} for (a,i),(s,_) in candidates.items()],
                           missing_semantic_bodies=[s['function'] for s in db['signatures'] if s['architecture']==domain and s.get('semantic') and not any(identity==s['id'] for _,identity in candidates)])
    for address, identity in valid:
        sig=candidates[address,identity][0]
        semantic=sig.get('semantic')
        if semantic:
            meanings.setdefault(address,set()).add(semantic)
            witnesses.append({'address':address,'semantic':semantic,'reference_id':identity,
                              'bound_local_callees':len(dependencies[address,identity]),
                              'method':'complete development primitive and bound static call graph'})
    # All matching variants at an address must agree. An ambiguous third
    # match must never restore a meaning removed by the second match.
    result={address:next(iter(values)) for address,values in meanings.items() if len(values)==1}
    return result,[w for w in witnesses if w['address'] in result]
