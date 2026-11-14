import json,sys,re,pickle
from collections import Counter, defaultdict
R1=re.compile(r'settle|transfer|pay|withdraw|execute|disburse|payout|charge|refund|mint|burn',re.I)
R4=re.compile(r'auth|confirm|token|signature|approval|whitelist|allowlist|limit|cap',re.I)
R5=re.compile(r'instruction|prompt|natural_?language|nl_|free_?text',re.I)
R6=re.compile(r'xml|pain001|iso20022|raw|payload',re.I)
R7=re.compile(r'webhook|callback|subscribe|url',re.I)
R8=re.compile(r'sandbox|dry.?run|test_?mode',re.I)
rule_hits=Counter(); server_risk=defaultdict(lambda:{'score':0,'rules':set(),'tools':0,'desc':''})
total=0
for line in sys.stdin:
    try: d=json.loads(line)
    except: continue
    total+=1
    name=d.get('tool_name') or ''; desc=d.get('tool_description') or ''
    props=list(((d.get('input_schema') or {}).get('properties') or {}).keys())
    sid=d.get('server_id')
    s=server_risk[sid]; s['tools']+=1
    if not s['desc']: s['desc']=desc[:100]
    if R1.search(name) or R1.search(desc[:120]):
        rule_hits['R1_funds_write']+=1; s['score']+=2; s['rules'].add('R1')
        if not any(R4.search(p) for p in props):
            rule_hits['R1b_funds_write_no_auth']+=1; s['score']+=3; s['rules'].add('R1b')
    if R5.search(name) or R5.search(desc[:150]):
        rule_hits['R5_nl_driven']+=1; s['score']+=1; s['rules'].add('R5')
    if R6.search(name) and not R8.search(name+' '+desc[:80]):
        rule_hits['R6_raw_passthrough']+=1; s['score']+=1; s['rules'].add('R6')
    if R7.search(name) and not any(re.search(r'sign|hmac|secret',p,re.I) for p in props):
        rule_hits['R7_webhook_unsigned']+=1; s['score']+=1; s['rules'].add('R7')
print('总工具数:', total)
for k,v in sorted(rule_hits.items()): print(f'{k}: {v}')
print('涉及 server 数:', len(server_risk))
top=sorted(server_risk.items(), key=lambda x:-x[1]['score'])[:15]
print()
print('=== TOP15 高危 server ===')
for sid,s in top:
    print(s['score'],'|',','.join(sorted(s['rules'])),'|',s['tools'],'工具 |',sid[:60])
pickle.dump({k:{'score':v['score'],'rules':list(v['rules']),'tools':v['tools']} for k,v in server_risk.items()}, open('/tmp/armory_risk.pkl','wb'))
