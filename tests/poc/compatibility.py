"""Installed VSCode test-host execution against the owned ordinary native root."""
import hashlib,json,os,plistlib,signal,subprocess,time
from pathlib import Path
from infra import InfrastructureUnavailable

def editor(j,ep,c,lazy):
    bundle=Path('/Applications/Visual Studio Code.app')
    info=bundle/'Contents/Info.plist'
    if not info.is_file():raise InfrastructureUnavailable('installed VSCode required')
    executable=bundle/'Contents/MacOS'/plistlib.loads(info.read_bytes())['CFBundleExecutable']
    cli=Path('/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code')
    if not executable.is_file():raise InfrastructureUnavailable('installed VSCode required')
    out=j.i.output/'editor';out.mkdir();ext=out/'extension';ext.mkdir();receipt=out/'receipt.json'
    (ext/'package.json').write_text(json.dumps({'name':'magus-owned-save','version':'0.0.1','publisher':'qualification','engines':{'vscode':'*'},'main':'extension.js','activationEvents':['*']}))
    (ext/'extension.js').write_text('exports.activate=()=>{}; exports.deactivate=()=>{};')
    path=Path(c['root'])/'instructions.md';old=path.read_bytes();expected=old+b'VSCode ordinary TextDocument.save qualification.\n'
    script="""const vscode=require('vscode');const fs=require('fs');const crypto=require('crypto');
exports.run=async()=>{const p=CONFIG;const doc=await vscode.workspace.openTextDocument(vscode.Uri.file(p.file));await vscode.window.showTextDocument(doc);const before=doc.getText();const e=new vscode.WorkspaceEdit();e.insert(doc.uri,doc.positionAt(before.length),p.append);if(!await vscode.workspace.applyEdit(e))throw Error('edit rejected');const saveWallMs=Date.now();const saved=await doc.save();if(!saved||doc.isDirty)throw Error('TextDocument.save failed');const actual=fs.readFileSync(p.file);fs.writeFileSync(p.receipt,JSON.stringify({api:'TextDocument.save',saveWallMs,version:vscode.version,saved,dirty:doc.isDirty,before,after:doc.getText(),sha256:crypto.createHash('sha256').update(actual).digest('hex'),pid:process.pid}));};""".replace('CONFIG',json.dumps({'file':str(path),'append':expected[len(old):].decode(),'receipt':str(receipt)}))
    test=ext/'test.js';test.write_text(script)
    argv=[str(executable),'--new-window','--disable-workspace-trust','--skip-welcome','--skip-release-notes','--disable-updates','--user-data-dir='+str(out/'userdata'),'--extensions-dir='+str(out/'extensions'),'--extensionDevelopmentPath='+str(ext),'--extensionTestsPath='+str(test),c['root']]
    version=j.i.run([str(cli),'--version']).stdout;before=ep.status(c);start=time.monotonic();log=open(out/'process.log','w');proc=subprocess.Popen(argv,stdout=log,stderr=log,start_new_session=True)
    j.i.write_json('editor-ownership.json',{'pid':proc.pid,'argv':argv,'version':version,'deadline_seconds':120})
    try:
        code=proc.wait(timeout=120);assert code==0,('VSCode test host',code)
        result=json.loads(receipt.read_text());assert result['saved'] is True and result['dirty'] is False and path.read_bytes()==expected and result['sha256']==hashlib.sha256(expected).hexdigest()
        saved_start=time.monotonic()-(time.time()-result['saveWallMs']/1000)
        j.until_visible(lambda:lazy.read('live/instructions.md')==expected.hex(),saved_start)
        prior={p['operation'] for p in before['status']['submissions']}
        progress=j.until(lambda:next((p for p in ep.status(c)['status']['submissions'] if p['operation'] not in prior and p['shared_receipt']),None),15)
        j.until_visible(lambda:ep.ready(c,progress['shared_receipt']['head']),saved_start)
        result.update(argv=argv,installed_version=version,elapsed_seconds=time.monotonic()-start,expected_sha256=hashlib.sha256(expected).hexdigest(),progress=progress,fixture_path='instructions.md',before_status=before)
    finally:
        if proc.poll() is None:os.killpg(proc.pid,signal.SIGTERM);proc.wait(timeout=10)
        log.close()
        # Only the exact isolated userdata instance belongs to this gate.
        cleanup_deadline=time.monotonic()+10
        while True:
            rows=subprocess.run(['ps','-axo','pid=,command='],capture_output=True,text=True,check=True).stdout
            remaining=[line for line in rows.splitlines() if str(out/'userdata') in line]
            if not remaining or time.monotonic()>=cleanup_deadline:break
            time.sleep(.05)
        j.i.write_json('editor-cleanup.json',{'pid':proc.pid,'exit':proc.returncode,'remaining':remaining});assert not remaining,remaining
    result['cleanup']={'remaining':[],'exit':proc.returncode};j.i.write_json('editor.json',result);return result
