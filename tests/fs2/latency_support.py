"""Import-safe exact receipt and disk-backed mounted fixture support."""
from connected import Lazy

def validate_receipts(progress,binding,replica):
 private=progress['private_receipt'];shared=progress['shared_receipt'];request=progress['request'];integration=progress['integration']
 assert private and shared and request and integration,'missing exact publication evidence'
 assert private['operation']==progress['operation']==request['operation']
 assert private['replica']==shared['replica']==request['replica']==integration['replica']==replica
 assert private['submitted_revision']==shared['submitted_revision']==request['revision']==progress['local_revision']
 assert private['original_view']==request['original_view']==binding['view']['view']
 assert private['original_head']==request['original_head']==binding['view']['head']
 assert integration['candidate_receipt']==private['receipt']
 assert shared['operation']==integration['operation'] and shared['operation']!=private['operation']
 assert shared['branch']==integration['branch']==binding['branch']

class DiskLazy(Lazy):
 def execute(self,code,settings=None,user='0:0',check=True):
  try:return super().execute("import os;os.environ['MAGUS_LATENCY_TRACE']='1'\n"+code,settings,user,check)
  finally:self.i.write_json(self.record_label+'-commands.json',self.commands)

 def __init__(self,j,suffix='disk-mounted'):
  self.record_label=suffix
  self.commands=[];self.i=j.i;self.image=j.image;self.tokens=j.tokens;self.mounts=[];self.holders=[];self.evidence={};self.owner=j
  volume=self.i.create('volume',suffix+'-state',[])
  self.daemon=self.i.create('container',suffix,['--network',self.i.ingress,'--cap-drop','ALL','--cap-add','SYS_ADMIN','--cap-add','DAC_OVERRIDE','--cap-add','SYS_CHROOT','--security-opt','apparmor=unconfined','--security-opt','no-new-privileges','--device','/dev/fuse','--memory','512m','--cpus','2','--pids-limit','256','-v',volume+':/private','--tmpfs','/shared:rw,nosuid,nodev,mode=755,size=16m',self.image,'python3','-c',"import os,signal,time;os.chmod('/private',0o700)\ndef reap(*a):\n while True:\n  try:p,s=os.waitpid(-1,os.WNOHANG)\n  except ChildProcessError:return\n  if p==0:return\nsignal.signal(signal.SIGCHLD,reap)\nwhile True:time.sleep(.2)"])
  self.i.docker('start',self.daemon)
  mounts=self.i.inspect('container',self.daemon)['Mounts'];assert any(m['Type']=='volume' and m['Destination']=='/private' and m['Name']==volume for m in mounts);self.i.write_json(suffix+'-disk-state-mount.json',{'state_volume':volume,'mounts':mounts,'scope':'Rancher VM-backed disk; no host/VM power-loss qualification'})
