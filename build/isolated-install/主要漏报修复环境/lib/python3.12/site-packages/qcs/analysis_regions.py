"""Avoid relifting already verified complete SM3/SM4 signature functions.

Only the executable byte ranges of an accepted whole-function witness are
excluded from the additional operation pass. Loaded bytes remain available
for literal/helper reads and every other executable byte is still analyzed.
This creates no finding and does not use input names or source hashes.
"""


def additional_regions(regions, report):
    intervals=[]
    for finding in report['findings']:
        if finding.get('engine')!='guomi_function_signature' or finding.get('algorithm') not in {'SM3','SM4'}:
            continue
        for witness in finding.get('matched_functions',[]):
            start=witness.get('address');length=witness.get('length')
            if isinstance(start,int) and isinstance(length,int) and length>0:
                intervals.append((start,start+length))
    result=[];skipped=0
    for base,offset,raw,flags in regions:
        if not flags&1:
            result.append((base,offset,raw,flags));continue
        cursor=base;end=base+len(raw)
        for left,right in sorted(intervals):
            left=max(base,left);right=min(end,right)
            if right<=cursor or left>=end:continue
            if left>cursor:
                result.append((cursor,offset+cursor-base,raw[cursor-base:left-base],flags))
            skipped+=right-max(cursor,left);cursor=right
        if cursor<end:
            result.append((cursor,offset+cursor-base,raw[cursor-base:],flags))
    return result,skipped
