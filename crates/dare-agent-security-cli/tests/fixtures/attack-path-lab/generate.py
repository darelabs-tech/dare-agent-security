"""Writes the ATTACK-PATH-LAB scenarios (Cycle 023, tasks 039-040).

Run from anywhere: `python3 crates/dare-agent-security-cli/tests/fixtures/attack-path-lab/generate.py`.
Each APL-NNN directory gets `lab.json` (engine runs), `system-model.json` and
`expected.json`. Nothing here is a graph fact: the facts come from the engines
when `tests/attack_path_lab.rs` runs them. See README.md.
"""
import glob, json, os, shutil
LAB=os.path.dirname(os.path.abspath(__file__))
ROOT=os.path.abspath(os.path.join(LAB,'../../../../..'))
STATIC=ROOT+'/crates/dare-attack-path/tests/fixtures/static-inputs/supply-chain'

def n(t,i): return f"node:{t}:{i}"
ALICE=n('human','alice'); MALLORY=n('human','mallory'); ASSIST=n('agent','assistant')
CRED=n('credential','index-admin-cred'); SVC=n('identity','index-service')
UP=n('data','uploaded-doc'); HB=n('data','handbook'); TBD=n('data','tenant-b-doc'); SAL=n('data','salary-doc')
TBM=n('data','tenant-b-memory'); PEER=n('agent','planner-peer'); INB=n('credential','inbound-token')
PAY=n('tool','payments-transfer'); UCH=n('data','user-channel'); CCH=n('data','conversation-channel')
LP=n('capability','left-pad'); SA=n('capability','support-agent')
def R(i): return f"node:resource:mcp-auth:${{run:{i}}}:mcp-invoices"

P={ # property ids
 'CT':'AGENT.RAG.CONTENT_TRUST_BOUNDARY','TDI':'AGENT.RAG.TENANT_DOCUMENT_ISOLATION','PA':'AGENT.IDENTITY.PRIVILEGE_AMPLIFICATION',
 'WT':'AGENT.MEMORY.WRITE_TRUST_BOUNDARY','MT':'AGENT.MEMORY.TENANT_BOUNDARY','PI':'AGENT.MEMORY.PROVENANCE_INTEGRITY','RA':'AGENT.MEMORY.RECALL_AUTHORITY_BOUNDARY',
 'SK':'AGENT.A2A.SKILL_AUTHORIZATION','PIB':'AGENT.A2A.PEER_IDENTITY_BINDING','MA':'AGENT.A2A.MESSAGE_AUTHENTICITY',
 'BOM':'AGENT.SUPPLY_CHAIN.BOM_COMPLETENESS','CS':'MCP.AUTH.CREDENTIAL_SEPARATION','DS':'AGENT.IDENTITY.DELEGATION_SCOPE_BOUNDARY','FOB':'MCP.AUTH.FINAL_OPERATION_BINDING','SRM':'MCP.IDENTITY.SELF_REPORTED_METADATA_BOUNDARY',
 'UI':'AGENT.GOAL.USER_INPUT_INSTRUCTION_BOUNDARY','XT':'AGENT.HUMAN_APPROVAL.CROSS_TURN_CONTINUITY',
}
def ent(i,t,name,**sec):
    e={"entity_id":i,"type":t,"display_name":name}
    if sec: e["security"]=sec
    return e
def al(engine,local,entity,run=None):
    a={"engine":engine,"local_id":local,"entity_id":entity}
    if run is not None: a["run"]=run
    return a
def model(mid, entities, aliases, entries=(), targets=(), declared=None):
    m={"schema_version":"1","model_id":mid,"target_id":"attack-path-lab","target_version":"023",
       "entities":entities,"aliases":aliases}
    if entries: m["entry_points"]=list(entries)
    if targets: m["targets"]=list(targets)
    if declared: m["declared_edges"]=declared
    return m
def run(engine,scenario): return {"engine":engine,"scenario":scenario}
def path(nodes,state,props=(),entry=None,target=None):
    p={"nodes":nodes,"control_state":state,"failed_properties":sorted(P[x] for x in props)}
    if entry: p["entry_class"]=entry
    if target: p["target_class"]=target
    return p

# shared entity sets
E_ALICE=ent('alice','HUMAN','Alice (tenant-a user)',tenant='tenant-a')
E_ASSIST=ent('assistant','AGENT','Support assistant')
E_CRED=ent('index-admin-cred','CREDENTIAL','Index admin credential',privileged=True)
E_SVC=ent('index-service','IDENTITY','Index service identity',tenant='tenant-a')
ID_ALIASES=[al('identity','user-7','alice'),al('identity','agent-1','assistant'),
            al('identity','svc-index','index-service'),al('identity','cred-index-admin','index-admin-cred')]

def model_a(entry='uploaded-doc'):
    ents=[E_ALICE,E_ASSIST,E_CRED,E_SVC,
          ent('uploaded-doc','DATA','Uploaded document',tenant='tenant-a'),
          ent('handbook','DATA','Employee handbook',tenant='tenant-a'),
          ent('tenant-b-doc','DATA','Tenant B document',tenant='tenant-b')]
    als=ID_ALIASES+[al('rag','user-7','alice'),al('rag','doc-upload','uploaded-doc'),
                    al('rag','doc-handbook','handbook'),al('rag','doc-other-tenant','tenant-b-doc')]
    return model('apl-class-a',ents,als,entries=[{"entity_id":entry,"class":"RETRIEVED_DOCUMENT"}])
def model_b():
    ents=[E_ALICE,E_ASSIST,E_CRED,E_SVC,ent('mallory','HUMAN','Mallory (tenant-b user)',tenant='tenant-b'),
          ent('tenant-b-memory','DATA','Tenant B memory item',tenant='tenant-b')]
    als=ID_ALIASES+[al('memory','user-7','alice'),al('memory','agent-1','assistant'),
                    al('memory','user-9','mallory'),al('memory','mem-other-tenant','tenant-b-memory')]
    return model('apl-class-b',ents,als,entries=[{"entity_id":"mallory","class":"LOW_PRIVILEGE_PRINCIPAL"},
                                                 {"entity_id":"alice","class":"LOW_PRIVILEGE_PRINCIPAL"}])
def model_c():
    ents=[E_ALICE,E_ASSIST,E_CRED,E_SVC,ent('planner-peer','AGENT','Planner peer agent',tenant='tenant-a')]
    als=ID_ALIASES+[al('a2a','sut','assistant'),al('a2a','planner','planner-peer')]
    return model('apl-class-c',ents,als)
def model_d():
    ents=[E_ALICE,E_ASSIST,E_CRED,E_SVC,ent('left-pad','CAPABILITY','left-pad package'),
          ent('support-agent','CAPABILITY','support-agent build')]
    als=ID_ALIASES+[al('supply-chain','left-pad','left-pad'),al('supply-chain','support-agent','support-agent')]
    declared=[{"type":"TRANSFERS_TO","source":"support-agent","target":"assistant","status":"INFERRED",
               "rationale":"The support-agent build is the code the assistant runs; no engine artifact states this deployment relation."}]
    return model('apl-class-d',ents,als,declared=declared)
def model_e(mcp_runs):
    ents=[E_ALICE,E_ASSIST,E_CRED,E_SVC,ent('inbound-token','CREDENTIAL','Inbound MCP token')]
    als=ID_ALIASES+[al('mcp-auth','user-7','alice'),al('mcp-auth','cred-inbound','inbound-token')]
    targets=[{"node_id":R(i),"class":"SENSITIVE_RESOURCE"} for i in mcp_runs]
    return model('apl-class-e',ents,als,targets=targets)
def model_f():
    ents=[E_ASSIST,ent('payments-transfer','TOOL','payments transfer tool',destructive=True),
          ent('user-channel','DATA','User prompt channel'),ent('conversation-channel','DATA','Conversation user channel')]
    als=[al('prompt-injection','sut','assistant'),al('multi-turn','sut','assistant'),
         al('prompt-injection','payment.transfer','payments-transfer'),al('multi-turn','transfer','payments-transfer'),
         al('prompt-injection','channel.user_prompt','user-channel'),al('multi-turn','channel.user','conversation-channel')]
    return model('apl-class-f',ents,als)
def model_h():
    ents=[E_ALICE,ent('tenant-b-memory','DATA','Tenant B memory item',tenant='tenant-b'),
          ent('salary-doc','DATA','Salary document',tenant='tenant-a')]
    als=[al('memory','user-7','alice'),al('rag','user-7','alice'),al('memory','mem-other-tenant','tenant-b-memory'),
         al('rag','doc-salary','salary-doc')]
    return model('apl-class-h',ents,als)

S={}
def sc(id_,cls,role,title,runs,mdl,exp,extra_files=None,declared=False):
    S[id_]=dict(lab={"id":id_,"class":cls,"role":role,"title":title,"runs":runs,**({"declared_edges":True} if declared else {})},model=mdl,exp=exp,files=extra_files)

# ---- Class A
A='A: retrieved document -> acting principal -> cross-tenant document or privileged credential'
PA1=[UP,ALICE,TBD]; PA2=[UP,ALICE,CRED]
sc('APL-001','A','attack',A,[run('rag-security','RAG-LAB-014'),run('rag-security','RAG-LAB-002'),run('identity-security','IDENTITY-LAB-006')],model_a(),
   {"exit":2,"paths":[path(PA1,'CONTROL_FAILED',['CT','TDI'],'RETRIEVED_DOCUMENT','CROSS_TENANT_RESOURCE'),
                      path(PA2,'CONTROL_FAILED',['CT','PA'],'RETRIEVED_DOCUMENT','PRIVILEGED_CREDENTIAL')]})
sc('APL-002','A','control',A,[run('rag-security','RAG-LAB-013'),run('rag-security','RAG-LAB-001'),run('identity-security','IDENTITY-LAB-019')],model_a(),
   {"exit":0,"paths":[path(PA2,'CONTROLS_HELD',[],'RETRIEVED_DOCUMENT','PRIVILEGED_CREDENTIAL')],"absent":[PA1],
    "no_failed_property":[P['CT'],P['TDI'],P['PA']]})
sc('APL-003','A','not_tested',A,[run('rag-security','RAG-LAB-014'),run('rag-security','RAG-LAB-002')],model_a(),
   {"exit":2,"paths":[path(PA1,'CONTROL_FAILED',['CT','TDI'],'RETRIEVED_DOCUMENT','CROSS_TENANT_RESOURCE')],"absent":[PA2]})
sc('APL-004','A','variant',A,[run('rag-security','RAG-LAB-014'),run('identity-security','IDENTITY-LAB-019')],model_a('handbook'),
   {"exit":2,"paths":[path([HB,ALICE,CRED],'CONTROL_UNDECIDED',[],'RETRIEVED_DOCUMENT','PRIVILEGED_CREDENTIAL')]})

# ---- Class B
B='B: memory written by one principal -> recalled by another -> privileged credential'
PB1=[MALLORY,TBM,ALICE,CRED]; PB2=[ALICE,TBM]
sc('APL-005','B','attack',B,[run('memory-security','MEMORY-LAB-008'),run('memory-security','MEMORY-LAB-004'),run('identity-security','IDENTITY-LAB-006')],model_b(),
   {"exit":2,"paths":[path(PB1,'CONTROL_FAILED',['WT','PA'],'LOW_PRIVILEGE_PRINCIPAL','PRIVILEGED_CREDENTIAL'),
                      path(PB2,'CONTROL_FAILED',['MT'],'LOW_PRIVILEGE_PRINCIPAL','CROSS_TENANT_RESOURCE')]})
sc('APL-006','B','control',B,[run('memory-security','MEMORY-LAB-007'),run('memory-security','MEMORY-LAB-003'),run('memory-security','MEMORY-LAB-001'),
   run('memory-security','MEMORY-LAB-009'),run('identity-security','IDENTITY-LAB-019')],model_b(),
   {"exit":2,"paths":[path([ALICE,CRED],'CONTROLS_HELD',[],'LOW_PRIVILEGE_PRINCIPAL','PRIVILEGED_CREDENTIAL')],"absent":[PB1,PB2],
    "no_failed_property":[P['WT'],P['PA'],P['MT'],P['PI'],P['RA']]})
sc('APL-007','B','not_tested',B,[run('memory-security','MEMORY-LAB-008'),run('memory-security','MEMORY-LAB-004')],model_b(),
   {"exit":2,"paths":[path(PB2,'CONTROL_FAILED',['MT'],'LOW_PRIVILEGE_PRINCIPAL','CROSS_TENANT_RESOURCE')],"absent":[PB1]})
sc('APL-008','B','attack',B,[run('memory-security','MEMORY-LAB-010'),run('memory-security','MEMORY-LAB-002'),run('identity-security','IDENTITY-LAB-019')],model_b(),
   {"exit":2,"paths":[path(PB1,'CONTROL_FAILED',['PI'],'LOW_PRIVILEGE_PRINCIPAL','PRIVILEGED_CREDENTIAL'),
                      path(PB2,'CONTROL_FAILED',['RA'],'LOW_PRIVILEGE_PRINCIPAL','CROSS_TENANT_RESOURCE')]})

# ---- Class C
C='C: peer agent -> assistant -> delegated service identity -> privileged credential'
PC=[PEER,ASSIST,SVC,CRED]
sc('APL-009','C','attack',C,[run('a2a','A2A-LAB-016'),run('identity-security','IDENTITY-LAB-004')],model_c(),
   {"exit":2,"paths":[path(PC,'CONTROL_FAILED',['SK'],'PEER_AGENT','PRIVILEGED_CREDENTIAL')]})
sc('APL-010','C','control',C,[run('a2a','A2A-LAB-010'),run('identity-security','IDENTITY-LAB-004')],model_c(),
   {"exit":2,"paths":[path(PC,'CONTROL_UNDECIDED',[],'PEER_AGENT','PRIVILEGED_CREDENTIAL')],"no_failed_property":[P['SK'],P['PIB']]})
sc('APL-011','C','not_tested',C,[run('a2a','A2A-LAB-016')],model_c(),{"exit":0,"absent":[PC]})
sc('APL-012','C','attack',C,[run('a2a','A2A-LAB-011'),run('identity-security','IDENTITY-LAB-004')],model_c(),
   {"exit":2,"paths":[path(PC,'CONTROL_FAILED',['PIB','SK'],'PEER_AGENT','PRIVILEGED_CREDENTIAL')]})

# ---- Class D
D='D: supply-chain component -> dependent build -> (declared) assistant -> service identity -> privileged credential'
PD=[LP,SA,ASSIST,SVC,CRED]
def scrun(): return {"engine":"supply-chain","scenario_file":"supply-chain/scenario.json","mode":"static","evidence_dir":"supply-chain/evidence"}
sc('APL-013','D','attack',D,[scrun(),run('identity-security','IDENTITY-LAB-004')],model_d(),
   {"exit":2,"paths":[path(PD,'CONTROL_FAILED',['BOM'],'SUPPLY_CHAIN_COMPONENT','PRIVILEGED_CREDENTIAL')]},extra_files='fail',declared=True)
sc('APL-014','D','control',D,[scrun(),run('identity-security','IDENTITY-LAB-004')],model_d(),
   {"exit":2,"paths":[path(PD,'CONTROL_UNDECIDED',[],'SUPPLY_CHAIN_COMPONENT','PRIVILEGED_CREDENTIAL')],"no_failed_property":[P['BOM']]},extra_files='pass',declared=True)
sc('APL-015','D','not_tested',D,[scrun()],model_d(),{"exit":0,"absent":[PD]},extra_files='fail',declared=True)

# ---- Class E
E='E: low-privilege principal -> inbound MCP token -> MCP server -> upstream credential passthrough -> MCP resource'
def MS(i): return f"node:mcp-server:mcp-auth:${{run:{i}}}:mcp-invoices"
def UPC(i): return f"node:credential:mcp-auth:${{run:{i}}}:cred-upstream"
sc('APL-016','E','attack',E,[run('mcp-auth-security','MCP-AUTH-LAB-027'),run('identity-security','IDENTITY-LAB-006')],model_e([0]),
   {"exit":2,"paths":[path([ALICE,INB,MS(0),UPC(0)],'CONTROL_FAILED',['CS'],'LOW_PRIVILEGE_PRINCIPAL','PRIVILEGED_CREDENTIAL'),
                      path([ALICE,INB,MS(0),UPC(0),R(0)],'CONTROL_FAILED',['CS'],'LOW_PRIVILEGE_PRINCIPAL','SENSITIVE_RESOURCE'),
                      path([ALICE,CRED],'CONTROL_FAILED',['PA'],'LOW_PRIVILEGE_PRINCIPAL','PRIVILEGED_CREDENTIAL')]})
sc('APL-017','E','control',E,[run('mcp-auth-security','MCP-AUTH-LAB-026'),run('mcp-auth-security','MCP-AUTH-LAB-031'),
   run('mcp-auth-security','MCP-AUTH-LAB-029'),run('identity-security','IDENTITY-LAB-019')],model_e([0,1,2]),
   {"exit":2,"paths":[path([ALICE,R(1)],'CONTROLS_HELD',[],'LOW_PRIVILEGE_PRINCIPAL','SENSITIVE_RESOURCE'),
                      path([ALICE,CRED],'CONTROLS_HELD',[],'LOW_PRIVILEGE_PRINCIPAL','PRIVILEGED_CREDENTIAL'),
                      path([ALICE,INB,MS(0),UPC(0),R(0)],'CONTROL_UNDECIDED',[],'LOW_PRIVILEGE_PRINCIPAL','SENSITIVE_RESOURCE')],
    "no_failed_property":[P['CS'],P['FOB'],P['PA'],P['SRM']]})
sc('APL-018','E','attack',E,[run('mcp-auth-security','MCP-AUTH-LAB-030'),run('mcp-auth-security','MCP-AUTH-LAB-033'),run('identity-security','IDENTITY-LAB-019')],model_e([0,1]),
   {"exit":2,"paths":[path([ALICE,INB,MS(0),UPC(0)],'CONTROL_FAILED',['SRM'],'LOW_PRIVILEGE_PRINCIPAL','PRIVILEGED_CREDENTIAL'),
                      path([ALICE,R(1)],'CONTROL_FAILED',['FOB'],'LOW_PRIVILEGE_PRINCIPAL','SENSITIVE_RESOURCE')]})

# ---- Class F
F='F: untrusted input or cross-turn conversation -> assistant -> destructive tool'
PF1=[UCH,ASSIST,PAY]; PF2=[CCH,ASSIST,PAY]
sc('APL-019','F','attack',F,[run('prompt-injection','PI-LAB-002'),run('multi-turn','multiturn-lab-025')],model_f(),
   {"exit":2,"paths":[path(PF1,'CONTROL_FAILED',['UI'],'UNTRUSTED_INPUT','DESTRUCTIVE_CAPABILITY'),
                      path(PF2,'CONTROL_UNDECIDED',[],'UNTRUSTED_INPUT','DESTRUCTIVE_CAPABILITY')]})
sc('APL-020','F','control',F,[run('prompt-injection','PI-LAB-001'),run('multi-turn','multiturn-lab-025')],model_f(),
   {"exit":2,"paths":[path(PF1,'CONTROLS_HELD',[],'UNTRUSTED_INPUT','DESTRUCTIVE_CAPABILITY')],"no_failed_property":[P['UI'],P['XT']]})
sc('APL-021','F','attack',F,[run('prompt-injection','PI-LAB-001'),run('multi-turn','multiturn-lab-026')],model_f(),
   {"exit":2,"paths":[path(PF1,'CONTROL_FAILED',['XT'],'UNTRUSTED_INPUT','DESTRUCTIVE_CAPABILITY'),
                      path(PF2,'CONTROL_FAILED',['XT'],'UNTRUSTED_INPUT','DESTRUCTIVE_CAPABILITY')]})

# ---- Class G: discontinuous
G='G: an access made under a principal the path never acquired (declared, unexplained authority change)'
TDOC=n('resource','ticket-doc')
def model_g(principal):
    ents=[E_ALICE,E_ASSIST,E_CRED,E_SVC,ent('mallory','HUMAN','Mallory (tenant-b user)',tenant='tenant-b'),
          ent('ticket-doc','RESOURCE','Ticket document',tenant='tenant-a'),ent('planner-peer','AGENT','Planner peer agent',tenant='tenant-a')]
    als=ID_ALIASES+[al('identity','document-123','ticket-doc'),al('tool','sut','assistant'),
                    al('a2a','sut','assistant'),al('a2a','planner','planner-peer')]
    declared=[{"type":"CAN_REACH","source":"assistant","target":"ticket-doc","status":"INFERRED",
               "authority":{"principal":principal},
               "rationale":"Deployment note: the assistant's document connector runs under this principal. No engine artifact explains how the assistant acquired it."}]
    return model('apl-class-g',ents,als,targets=[{"entity_id":"ticket-doc","class":"SENSITIVE_RESOURCE"}],declared=declared)
sc('APL-022','G','structural',G,[run('identity-security','IDENTITY-LAB-001'),run('tool-security','TOOL-LAB-011')],model_g('mallory'),
   {"exit":2,"discontinuous":[{"nodes":[ALICE,ASSIST,TDOC],"at":1}],
    "paths":[path([ALICE,TDOC],'CONTROLS_HELD',[],'LOW_PRIVILEGE_PRINCIPAL','SENSITIVE_RESOURCE')]},declared=True)
sc('APL-023','G','structural',G,[run('identity-security','IDENTITY-LAB-004'),run('a2a','A2A-LAB-016')],model_g('index-service'),
   {"exit":2,"discontinuous":[{"nodes":[PEER,ASSIST,TDOC],"at":1},{"nodes":[ALICE,ASSIST,TDOC],"at":1}],
    "paths":[path([ALICE,ASSIST,SVC,CRED,TDOC],'CONTROL_FAILED',['DS'],'LOW_PRIVILEGE_PRINCIPAL','SENSITIVE_RESOURCE')]},declared=True)

# ---- Class H: alias-only merging
H='H: the same local id in two engines joins only through a system-model alias'
def rs(t,e,i,l): return f"node:{t}:{e}:${{run:{i}}}:{l}"
sc('APL-024','H','structural',H,[run('memory-security','MEMORY-LAB-008'),run('rag-security','RAG-LAB-004')],None,
   {"exit":2,"node_ids":[rs('human','memory',0,'user-7'),rs('human','rag',1,'user-7')],
    "absent":[[rs('data','memory',0,'mem-other-tenant'),rs('human','memory',0,'user-7'),rs('data','rag',1,'doc-salary')],
              [rs('data','memory',0,'mem-other-tenant'),rs('human','rag',1,'user-7'),rs('data','rag',1,'doc-salary')]]})
sc('APL-025','H','structural',H,[run('memory-security','MEMORY-LAB-008'),run('rag-security','RAG-LAB-004')],model_h(),
   {"exit":2,"paths":[path([TBM,ALICE,SAL],'CONTROL_FAILED',['TDI'],'MEMORY_WRITE','SENSITIVE_RESOURCE')]})

# ---- Class I: remote
I='I: an authorized remote (Cycle 022) run joined to a local identity run'
sc('APL-026','I','structural',I,[{"engine":"replay-capture"},run('identity-security','IDENTITY-LAB-001')],
   model('apl-class-i',[E_ALICE,E_ASSIST,E_CRED,E_SVC],ID_ALIASES),
   {"exit":2,"paths":[path([ALICE,CRED],'CONTROL_UNDECIDED',[],'LOW_PRIVILEGE_PRINCIPAL','PRIVILEGED_CREDENTIAL')],
    "artifacts":{"dynamic_authorized":1,"unprojected":{"MULTI_TURN_RESULT_ONLY":1}},
    "summary_contains":["1 from authorized remote runs"]})

def dump(path,v):
    with open(path,'w') as f: f.write(json.dumps(v,indent=2)+'\n')
for old in glob.glob(f"{LAB}/APL-*"): shutil.rmtree(old)
for k,v in S.items():
    d=f"{LAB}/{k}"; os.makedirs(d)
    dump(f"{d}/lab.json",v['lab'])
    if v['model']: dump(f"{d}/system-model.json",v['model'])
    dump(f"{d}/expected.json",v['exp'])
    if v['files']:
        os.makedirs(f"{d}/supply-chain/evidence")
        shutil.copy(f"{STATIC}/scenario.json",f"{d}/supply-chain/scenario.json")
        shutil.copy(f"{STATIC}/evidence/manifest.json",f"{d}/supply-chain/evidence/manifest.json")
        bom=json.load(open(f"{STATIC}/evidence/app.cdx.json"))
        if v['files']=='pass':
            for c in bom['components']:
                c.setdefault('hashes',[{"alg":"SHA-256","content":"b"*64}])
        dump(f"{d}/supply-chain/evidence/app.cdx.json",bom)
print(f"wrote {len(S)} scenarios")
