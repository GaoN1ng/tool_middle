"""Expand definition headers through their actual function-like macros.

Only invocations immediately followed by a body are considered. Substitution
uses definition tokens, never a macro-name convention. Replacements keep byte
length and newline count so body/call offsets retain their original meaning.
This is deliberately not a configuration-selecting C preprocessor.
"""
import re


def arguments(raw, start):
    depth=0;begin=start+1;parts=[]
    for at in range(start,len(raw)):
        c=raw[at:at+1]
        if c==b'(':depth+=1
        elif c==b')':
            depth-=1
            if not depth:
                parts.append(raw[begin:at].strip());return parts,at+1
        elif c==b',' and depth==1:parts.append(raw[begin:at].strip());begin=at+1
    return None,None


def expand(raw, cpp, contexts=()):
    from .guomi.source_semantics import parser, walk, txt
    definitions={};ambiguous=set();objects={}
    for content in [*contexts,raw]:
        for node in walk(parser(cpp).parse(content).root_node):
            if node.type=='preproc_def':
                n=node.child_by_field_name('name');v=node.child_by_field_name('value')
                if n is not None:objects.setdefault(txt(n).encode(),set()).add(v.text.strip() if v else b'')
            if node.type!='preproc_function_def':continue
            name=txt(node.child_by_field_name('name')).encode()
            params=node.child_by_field_name('parameters');value=node.child_by_field_name('value')
            if not value:continue
            body=re.sub(rb'\\\r?\n',b' ',value.text).strip()
            # Export/calling alignment annotations do not change the declared
            # identifier or parameter list. Normalise only these explicit
            # declaration qualifiers before comparing conditional variants.
            body=re.sub(rb'__declspec\s*\(\s*(?:dllimport|dllexport)\s*\)',b'',body)
            body=re.sub(rb'__attribute__\s*\(\(\s*force_align_arg_pointer\s*\)\)',b'',body)
            body=re.sub(rb'\bextern\b',b'',body)
            body=re.sub(rb'\s+',b' ',body).strip()
            entry=([txt(p).encode() for p in params.named_children],body)
            if name in definitions and definitions[name]!=entry:ambiguous.add(name)
            else:definitions[name]=entry
    def convention(name,seen=()):
        if name in seen or len(seen)>6 or name not in objects:return False
        for value in objects[name]:
            if not value:continue
            if value in {b'__cdecl',b'__stdcall',b'__fastcall',b'__vectorcall'}:continue
            if re.fullmatch(rb'__attribute(?:__)?\s*\(\(?\s*(?:cdecl|stdcall|fastcall)\s*\)?\)',value):continue
            if re.fullmatch(rb'[A-Za-z_]\w*',value) and convention(value,(*seen,name)):continue
            return False
        return True
    conventions={name for name in objects if convention(name)}
    def instantiate(value,depth=0):
        if depth>6:return None
        for match in reversed(list(re.finditer(rb'\b([A-Za-z_]\w*)\s*\(',value))):
            name=match[1]
            if name not in definitions or name in ambiguous:continue
            params,body=definitions[name];args,end=arguments(value,value.find(b'(',match.start()))
            if args is None or len(params)!=len(args) or b'#' in body:continue
            bindings=dict(zip(params,args))
            body=re.sub(rb'\b[A-Za-z_]\w*\b',lambda m:bindings.get(m[0],m[0]),body)
            expanded=instantiate(body,depth+1)
            if expanded is None:return None
            value=value[:match.start()]+expanded+value[end:]
        return re.sub(rb'\b[A-Za-z_]\w*\b',lambda m:b'' if m[0] in conventions else m[0],value)
    changes=[]
    for match in re.finditer(rb'(?m)^[ \t]*([A-Za-z_]\w*)\s*\(',raw):
        if match[1] not in definitions or match[1] in ambiguous:continue
        start=match.start(1);args,end=arguments(raw,raw.find(b'(',start))
        if end is None or not re.match(rb'\s*\{',raw[end:]):continue
        header=instantiate(raw[start:end])
        if header is None or header==raw[start:end] or any(c in header for c in (b'{',b'}',b';',b'#')):continue
        tree=parser(cpp).parse(header+b'{}')
        funcs=[n for n in tree.root_node.named_children if n.type=='function_definition']
        if len(funcs)!=1:continue
        # An error in the parameter list could invent argument bindings.
        decl=funcs[0].child_by_field_name('declarator')
        if decl is None or decl.has_error:continue
        original=raw[start:end];lines=original.count(b'\n')
        header=re.sub(rb'\s+',b' ',header).strip()
        if len(header)+lines>len(original):continue
        replacement=header+b' '*(len(original)-len(header)-lines)+b'\n'*lines
        changes.append((start,end,replacement,match[1].decode()))
    for start,end,replacement,_ in reversed(changes):raw=raw[:start]+replacement+raw[end:]
    return raw,[{'offset':start,'macro':name,'method':'actual declaration macro token substitution'}
                for start,_,_,name in changes]
