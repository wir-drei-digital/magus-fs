"""Independent stdlib SigV4 probe, run only by fixture admin inside private net."""
import datetime
import hashlib
import hmac
import http.client
import json
import sys
from urllib.parse import quote

def request(method, path, body, anonymous=False):
    credentials=json.load(open('/control/s3-client.json'))
    now=datetime.datetime.now(datetime.timezone.utc)
    stamp=now.strftime('%Y%m%dT%H%M%SZ'); date=stamp[:8]
    digest=hashlib.sha256(body).hexdigest()
    headers={'host':'s3:8333','x-amz-content-sha256':digest,'x-amz-date':stamp}
    signed=';'.join(sorted(headers))
    canonical='\n'.join([method,quote(path,safe='/'),'', ''.join(k+':'+headers[k]+'\n' for k in sorted(headers)),signed,digest])
    scope=date+'/us-east-1/s3/aws4_request'
    message='AWS4-HMAC-SHA256\n'+stamp+'\n'+scope+'\n'+hashlib.sha256(canonical.encode()).hexdigest()
    key=('AWS4'+credentials['secret']).encode()
    for part in [date,'us-east-1','s3','aws4_request']:
        key=hmac.new(key,part.encode(),hashlib.sha256).digest()
    sig=hmac.new(key,message.encode(),hashlib.sha256).hexdigest()
    headers['Authorization']='AWS4-HMAC-SHA256 Credential='+credentials['access']+'/'+scope+', SignedHeaders='+signed+', Signature='+sig
    if anonymous:
        del headers['Authorization']
    c=http.client.HTTPConnection('s3',8333,timeout=5)
    c.request(method,quote(path,safe='/'),body,headers)
    r=c.getresponse(); data=r.read(); c.close()
    print(json.dumps({'status':r.status,'size':len(data),'sha256':hashlib.sha256(data).hexdigest(),'etag':r.getheader('etag')}))
    return 0 if r.status in (200,201,204,409) else 1

if __name__=='__main__':
    sys.exit(request(sys.argv[1],sys.argv[2],sys.stdin.buffer.read(),'--anonymous' in sys.argv[3:]))
