"""Manage only resources created and recorded by this invocation."""
import os,pathlib,shutil,uuid
class OwnedOutput:
 def __init__(self,path):
  self.path=pathlib.Path(path)
  if not self.path.is_absolute(): raise ValueError('output must be absolute')
  if self.path.exists() or self.path.is_symlink(): raise ValueError('output must be new')
  self.path=self.path.parent.resolve(strict=True)/self.path.name
  self.token=uuid.uuid4().hex
  self.path.mkdir()
  self.marker=self.path/'.fs0-owned'
  self.marker.write_text(self.token)
  self.processes=[]
 def own_process(self,process): self.processes.append(process); return process
 def cleanup(self,remove_output=True):
  errors=[]
  for p in reversed(self.processes):
   try:
    if p.poll() is None: p.terminate(); p.wait(timeout=5)
   except Exception as e: errors.append(str(e))
  if remove_output:
   try:
    if self.path.is_symlink() or self.marker.is_symlink() or self.marker.read_text()!=self.token: raise ValueError('ownership mismatch')
    shutil.rmtree(self.path)
   except Exception as e: errors.append(str(e))
  return errors
