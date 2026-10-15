#!/usr/bin/env python3
"""Stream-verify portable submission payloads without extracting an archive."""
import argparse
import hashlib
import json
from pathlib import Path
import tarfile

ROOT=Path(__file__).resolve().parents[1]


def digest(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive',type=Path,default=ROOT/'build/dist/ustc_tool_middle.tar.gz')
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();output=args.output.resolve()
    if not output.is_relative_to(ROOT/'build') or output.exists():raise ValueError('Use a new output file below build/')
    required={}
    for directory in ('src','tools','tests','licenses','Samples','build/runtime','build/wheelhouse','build/reports/major-gaps-20261015'):
        for p in (ROOT/directory).rglob('*'):
            if p.is_file() and not p.is_symlink() and '__pycache__' not in p.parts and p.suffix!='.pyc':required[str(p.relative_to(ROOT))]=digest(p)
    for name in ('readme.md','todo.md','LICENSE','pyproject.toml','setup.py','setup.cfg','requirements.lock',
                 'build/checks/major-gaps-release-stable-freeze.json','build/history/major-gaps-20261015/frozen-release-stable-package.tar.gz'):
        p=ROOT/name;required[name]=digest(p)
    issues=[];seen=set();files=0
    with tarfile.open(args.archive,'r|gz') as archive:
        for member in archive:
            path=Path(member.name)
            if path.parts[:1]!=(ROOT.name,) or '..' in path.parts or path.is_absolute():
                issues.append('Invalid archive member: '+member.name);continue
            relative=str(Path(*path.parts[1:]));parts=path.parts[1:]
            if member.issym() or member.islnk():issues.append('Unexpected archive link: '+relative)
            if not member.isfile():continue
            files+=1
            if '__pycache__' in parts or (len(parts)>1 and parts[0]=='build' and parts[1] in {'experiments','venv','cache','tmp','isolated-install'}):
                issues.append('Excluded generated tree included: '+relative)
            if relative in required:
                if relative in seen:issues.append('Duplicate critical payload: '+relative)
                seen.add(relative);stream=archive.extractfile(member)
                if hashlib.file_digest(stream,'sha256').hexdigest()!=required[relative]:issues.append('Payload digest mismatch: '+relative)
    issues.extend('Missing critical payload: '+name for name in sorted(required.keys()-seen))
    result=dict(passed=not issues,archive=str(args.archive),archive_bytes=args.archive.stat().st_size,
                archive_sha256=digest(args.archive),files=files,verified_critical_payload_files=len(seen),issues=issues)
    output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(result,ensure_ascii=False,indent=2));return 0 if result['passed'] else 1

if __name__=='__main__':raise SystemExit(main())
