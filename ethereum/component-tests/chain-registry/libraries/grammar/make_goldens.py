"""Fixed scalar syntax examples; independent RFC3986 regex + Python IPv6 oracle.
No network, request construction, fuzzing, payload delivery or protocol runtime.
"""
from pathlib import Path
import ipaddress,json,re
root=Path(__file__).resolve().parent
unreserved=r'[A-Za-z0-9._~-]';sub=r"[!$&'()*+,;=]";pct=r'%[0-9A-Fa-f]{2}'
pchar=f'(?:{unreserved}|{sub}|{pct}|[:@])'
uri=re.compile(r'(?ai:https)://(?P<authority>[^/?#]+)(?P<path>/(?:'+pchar+r'|/)*)?(?:\?(?P<query>(?:'+pchar+r'|[/?])*))?')
regname=re.compile(f'(?:{unreserved}|{sub}|{pct})+')
ipfuture=re.compile(r'[vV][0-9A-Fa-f]+\.(?:'+unreserved+'|'+sub+r'|:)+')
def valid_uri(s):
 if not s.isascii():return False
 if not 1<=len(s.encode())<=2048:return False
 m=uri.fullmatch(s)
 if m is None:return False
 authority=m['authority']
 if authority.startswith('['):
  a=re.fullmatch(r'\[([^\]]+)\](?::[0-9]*)?',authority)
  if a is None:return False
  host=a[1]
  if ipfuture.fullmatch(host):return True
  try:ipaddress.IPv6Address(host)
  except ipaddress.AddressValueError:return False
  return '%' not in host # RFC3986 alone does not define a zone-id suffix.
 a=re.fullmatch(r'([^:]+)(?::[0-9]*)?',authority)
 return a is not None and regname.fullmatch(a[1]) is not None
cases=[]
def add(name,method,args,ok,error='887efaa5'):
 if method=='httpsUri':assert valid_uri(args[0])==ok,(name,args)
 cases.append(dict(name=name,method=method,arguments=args,expected_hex=args[0].encode().hex() if ok else error,exception=None if ok else 'revert'))
for text in ['a','A0_z-.unit','a'*64,'.x','...','0']:
 add('agent-'+str(len(cases)),'name',[text,True],True)
for text in ['', '.', '..','a/b','a@b','x~y','é']:
 add('bad-agent-'+str(len(cases)),'name',[text,True],False)
add('long-agent','name',['a'*65,True],False,'8b54271a')
for text in ['a','Key_0-name','k'*32]:add('key-'+str(len(cases)),'name',[text,False],True)
for text in ['', '.', '..','key.name','x~y','é']:add('bad-key-'+str(len(cases)),'name',[text,False],False)
add('long-key','name',['k'*33,False],False,'8b54271a')
for text in ['https',''.join(map(chr,range(64))),''.join(map(chr,range(64,128)))]:add('type-'+str(len(cases)),'serviceType',[text],True)
add('empty-type','serviceType',[''],False)
add('long-type','serviceType',['a'*65],False,'8b54271a')
add('nonascii-type','serviceType',['é'],False)
positive=[
 'https://x','HtTpS://Example.TEST','https://example.test/','https://example.test:',
 'https://example.test:443/','https://example.test:65536/','https://example.test:000000000000000000000000000000000000000000/',
 'https://example.test/a@b?user=x@y','https://example.test/a:b//c/./../x','https://example.test?','https://example.test/a??x/?@b',
 'https://%41.example.test/%00/%23/%ff?x=%40','https://a!$&\'()*+,;=.test/',
 'https://192.0.2.1/','https://999.0.0.0/','https://./',
 'https://[::]/','https://[::1]/','https://[2001:db8::1]:443/path',
 'https://[1:2:3:4:5:6:7:8]/','https://[1:2:3:4:5:6:7::]/','https://[::1:2:3:4:5:6:7]/',
 'https://[1:2::3:4:5:6:7]/','https://[::ffff:192.0.2.128]/','https://[1:2:3:4:5:6:192.0.2.1]/',
 'https://[::192.0.2.1]:/?x=@y','https://[v1.a:b!]/','https://[VF.alpha._~$]/',
 'https://example.test/'+('a'*(2048-len('https://example.test/')))
]
negative=[
 '','https://','http\u017f://x','http://example.test','https:example.test','https:/example.test','https:///a','https://?x=y',
 'https://user@example.test/','https://user:password@example.test/','https://:443/','https://example.test#',
 'https://example.test/a#fragment','https://example.test/a b','https://example.test/\n','https://example.test/\x7f',
 'https://example.test/é','https://example.test/%','https://example.test/%0','https://example.test/%0g',
 'https://%zz.example.test/','https://example.test:port/','https://example.test:1:2/',
 'https://example.test/path[bad]','https://example.test?x=[bad]','https://example.test/\\path',
 'https://[]/','https://[::1/','https://[::1]suffix/','https://[::1]:x/',
 'https://[v.a]/','https://[v1.]/','https://[vG.foo]/','https://[v1.a%20]/','https://[v1.a@b]/',
 'https://[::%25zone]/','https://[1:2:3:4:5:6:7]/','https://[1:2:3:4:5:6:7:8:9]/',
 'https://[1:2:3:4:5:6:7:8::]/','https://[:1]/','https://[1:]/','https://[:::]/','https://[1::2::3]/',
 'https://[12345::]/','https://[gggg::]/','https://[1:2:3:4:5:192.0.2.1]/',
 'https://[::192.0.2]/','https://[::192.0.2.256]/','https://[::192.0.02.1]/','https://[::192.0.2.1:2]/',
 'https://[::192.0.x.1]/','https://[::192.0.2.1.4]/','https://[::1.2.3.4444]/',
 'https://example.test/'+('a'*(2049-len('https://example.test/')))
]
for i,text in enumerate(positive):add('uri-allow-'+str(i),'httpsUri',[text],True)
for i,text in enumerate(negative):add('uri-refuse-'+str(i),'httpsUri',[text],False,'8b54271a' if len(text.encode())>2048 else '887efaa5')
assert len({c['name'] for c in cases})==len(cases)
(root/'goldens.json').write_text(json.dumps({'scope':'Finite scalar syntax unit controls only; no fetch, authentication, authority, RPC or Registry admission','references':['https://www.rfc-editor.org/rfc/rfc3986.html#appendix-A'],'cases':cases},indent=2)+'\n')
print('Grammar fixed cases',len(cases))
