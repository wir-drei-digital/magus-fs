"""Direct Linux production CLI journey inside the source-matched fixture container."""
import hashlib,json,os,secrets,subprocess,sys
from pathlib import Path

def main():
    settings=json.load(sys.stdin)
    root=Path('/tmp/fs2-client-'+secrets.token_hex(8));root.mkdir(mode=0o700)
    control=root/'control';control.mkdir(mode=0o700);content=root/'content';content.mkdir(mode=0o700)
    def private(name,value):
        p=control/name;fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as f:f.write(value if isinstance(value,str) else json.dumps(value))
        return p
    def call(binary,*args):
        p=subprocess.run([binary,*map(str,args)],text=True,capture_output=True,timeout=65);assert p.returncode==0,(args,p.stdout,p.stderr);return json.loads(p.stdout)
    config={'replica':{'replica':settings['replica'],'authorities':[{'principal':settings['principal'],'uid':os.geteuid(),'gid':os.getegid(),'primary_group':settings['group'],'groups':[settings['group']],'dac_override':False,'ownership_transfer':False}],'content_roots':[str(content)],'cache_bytes':96*1024*1024},'root':str(content),'policy':{'included_roots':['.'],'excluded_prefixes':[]},'creation_umask':18}
    ca=private('ca.pem',Path('/control/ca.crt').read_text());token=private('token',settings['token'])
    profile=private('profile.json',{'endpoint':'https://service:8443','namespace':settings['namespace'],'replica':settings['replica'],'ca_file':str(ca),'token_file':str(token)})
    state=root/'state';call('magus-fs','init','--state',state,'--config',private('config.json',config))
    attached=call('magus-fs','sync','attach','--state',state,'--profile',profile,'--branch','main');assert attached['counters']['downloaded_body_bytes']==0
    cold=call('client_probe',state,'read','reports/large',0,4096,root/'head.bin');assert hashlib.sha256((root/'head.bin').read_bytes()).hexdigest()==settings['head_hash']
    warm=call('client_probe',state,'read','reports/large',0,4096,root/'warm.bin');assert warm['counters']['downloaded_body_bytes']==0
    call('client_probe',state,'write','reports/linux','linux ordinary client')
    op='operation:'+secrets.token_hex(16);revision=call('magus-fs','checkpoint','--state',state,'--operation-id',op)['revision']
    private_result=call('magus-fs','sync','run','--state',state,'--revision',revision,'--operation-id',op)
    assert private_result['progress']['state']=='PrivateRemote' and private_result['progress']['applied_revision'] is None
    print(json.dumps({'root':str(root),'attachment':attached,'cold':cold,'warm':warm,'private':private_result}))
if __name__=='__main__':main()
