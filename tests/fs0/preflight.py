import os,platform,shutil,subprocess

def check(which=shutil.which):
 required=['cargo','rustc','python3']
 tools={name:which(name) for name in required}
 system=platform.system()
 if system=='Darwin': tools['mount_nfs']=which('mount_nfs'); mount={'adapter':'NFS','status':'unproven','reason':'real mount qualification required'}
 elif system=='Linux':
  tools['fusermount']=which('fusermount3') or which('fusermount')
  mount={'adapter':'FUSE','device':os.path.exists('/dev/fuse'),'status':'unproven','reason':'real mount qualification required'}
 else: mount={'status':'unsupported','reason':system}
 missing=[k for k,v in tools.items() if v is None]
 if system=='Linux' and not mount['device']: missing.append('/dev/fuse')
 if system not in ('Darwin','Linux'): missing.append('supported OS')
 versions={}
 for name in ('cargo','rustc','python3'):
  if tools[name]:
   try: versions[name]=subprocess.run([tools[name],'--version'],capture_output=True,text=True,timeout=5,check=True).stdout.strip()
   except (OSError,subprocess.SubprocessError): missing.append(name+' version'); versions[name]='unavailable'
 return {'system':system,'machine':platform.machine(),'tools':tools,'versions':versions,'mount':mount,'missing':missing,'exit_code':2 if missing else 0}
