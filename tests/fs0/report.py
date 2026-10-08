import json
MANDATORY=('mount','range_reads','private_writes','readonly_view','permissions','cleanup')
def qualifies(cases,cleanup_errors):
 return not cleanup_errors and all(cases.get(k)=='passed' for k in MANDATORY)
def save(path,preflight,cases,cleanup_errors):
 result={'preflight':preflight,'cases':cases,'cleanup_errors':cleanup_errors,'passed':qualifies(cases,cleanup_errors)}
 path.write_text(json.dumps(result,indent=2)+'\n'); return result
