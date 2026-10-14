"""Bounded local header context for actual macro/scalar helper expansion.

Headers supply definitions, not stand-alone algorithm findings. No compiler,
network, system include path, include-name signature or target execution is used.
"""
import hashlib
import re
from pathlib import Path

MAX_FILES=48
MAX_BYTES=1024*1024
MAX_DEPTH=6

def available_code(text):
    from ..source import lex_cpp
    code,_,_=lex_cpp(text)
    inactive=[];masked=[]
    for line in code.splitlines(keepends=True):
        directive=re.match(r'\s*#\s*(if|ifdef|ifndef|else|elif|endif)\b(.*)',line)
        if directive:
            d,arg=directive.groups()
            if d in {'if','ifdef','ifndef'}:inactive.append([d=='if' and arg.strip() in {'0','1'},d=='if' and arg.strip()=='0'])
            elif d=='else' and inactive and inactive[-1][0]:inactive[-1][1]=not inactive[-1][1]
            elif d=='elif' and inactive:inactive[-1]=[False,False]
            elif d=='endif' and inactive:inactive.pop()
        masked.append(''.join('\n' if c=='\n' else ' ' for c in line) if any(x[1] for x in inactive) else line)
    return ''.join(masked)

def load_context(path, text):
    from ..source import lex_cpp
    from ..text import decode_source
    from .source_semantics import Analysis
    path=Path(path).resolve()
    # Choose the nearest checkout boundary; unlicensed isolated fixtures can
    # still resolve siblings without crawling the rest of the workspace.
    root=path.parent
    for parent in [path.parent,*path.parents]:
        if any((parent/n).is_file() for n in ('LICENSE','LICENSE.txt','LICENSE.md','COPYING','LICENCE')):
            root=parent;break
        if (parent/'.git').exists():break
    search=[path.parent,*[p for p in path.parents if p.is_relative_to(root)],root/'include',root]
    seen={path};queue=[(path,text,0)];contexts=[];records=[];size=0;limited=False
    while queue:
        current,content,depth=queue.pop(0)
        if depth>=MAX_DEPTH:continue
        # The lexer extracts actual include directives and masks comments and
        # literals. The original matching line supplies the quoted/angle path.
        code=available_code(content)
        original=content.splitlines();masked=code.splitlines()
        for line,visible in zip(original,masked):
            if not re.match(r'\s*#\s*include\b',visible):continue
            match=re.match(r'\s*#\s*include\s*[<"]([^>"\r\n]+)[>"]',line)
            if not match:continue
            name=Path(match[1])
            if name.is_absolute():continue
            found=None
            for base in [current.parent,*search]:
                candidate=(base/name).resolve()
                if candidate.is_relative_to(root) and candidate.is_file():
                    found=candidate;break
            if found is None or found in seen:continue
            if found.suffix.lower() not in {'.h','.hpp','.hxx','.inc'}:continue
            if len(records)>=MAX_FILES or found.stat().st_size+size>MAX_BYTES:
                limited=True;continue
            raw=found.read_bytes();size+=len(raw);seen.add(found)
            header,_=decode_source(raw)
            cpp=path.suffix.lower() in {'.cpp','.cc','.cxx','.hpp','.hxx'} or path.name.endswith('.cc.inc')
            contexts.append(Analysis(available_code(header).encode(),cpp))
            records.append({'path':str(found),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)})
            queue.append((found,header,depth+1))
    return contexts,{'files':records,'bytes':size,'limited':limited,
        'scope':'Local macros and actual bounded scalar definitions; headers are not scanned as independent algorithm implementations'}

def attach_context(analysis, contexts):
    # Conflicting include variants cannot be resolved without preprocessing.
    # Decline them; local definitions/macros retain their lexical precedence.
    for attribute in ('functions','macros','tables','constants'):
        candidates={};ambiguous=set()
        for context in contexts:
            for name,value in getattr(context,attribute).items():
                if attribute in {'functions','macros'} and value[1] is None:continue
                canonical=value[1].text if attribute in {'functions','macros'} else value
                if name in candidates and candidates[name][0]!=canonical:ambiguous.add(name)
                else:candidates[name]=(canonical,value)
        local=getattr(analysis,attribute)
        for name,(_,value) in candidates.items():
            if name in local or name in ambiguous:continue
            local[name]=value
            if attribute=='macros':analysis.context_macros[name]=value
            elif attribute=='constants':analysis.constant_versions[name]=[(-1,value)]
