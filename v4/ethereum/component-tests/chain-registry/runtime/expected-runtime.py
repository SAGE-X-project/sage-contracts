"""Independent Python model for the fixed ordinary constructor test trace.

Only typed owned fixture values and explicit VM block times are inputs. No
observed Registry return bytes, signing, VM, network or transaction producer.
Not a general interpreter or an operating Source/finality model.
"""
import base64,copy,hashlib,json,sys

def jcs(value):
    def check(item):
        if isinstance(item,str):assert item.isascii()
        elif type(item)is int:assert 0<=item<=9007199254740991
        elif type(item)is list:
            for entry in item:check(entry)
        elif type(item)is dict:
            for key,entry in item.items():assert type(key)is str;check(key);check(entry)
        else:assert item is None or type(item)is bool
    check(value)
    return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()

def digest(value):return base64.urlsafe_b64encode(hashlib.sha256(value).digest()).decode().rstrip('=')

def expected_trace(fixture):
    assert set(fixture)=={'registry','initial','added','rotated_services','operator','admitted','salt','end_mode'}
    assert fixture['end_mode']in['explicit-deactivate','last-signing-revoke']
    record=copy.deepcopy(fixture['initial']);principal=record['controller'];registry=fixture['registry'];operator=fixture['operator']
    assert record['state']=='created'and record['version']=='1'and record['id'].startswith('did:sage:'+registry+':')
    assert [x['name']for x in record['keys']]==['a-kem','z-sign']
    assert [x['alg']for x in record['keys']]==['x25519','ed25519']
    assert fixture['added']['name']=='m-add'and fixture['added']['alg']=='ed25519'and fixture['added']['state']=='accepted'
    assert len(fixture['admitted'])==13 and all(type(x)is int and 0<=x<=9007199254740991 for x in fixture['admitted'])
    assert fixture['admitted']==sorted(fixture['admitted'])
    for address in [principal,operator]:assert len(address)==42 and address.startswith('0x')and address==address.lower()
    grants=[];result=[]
    grant=lambda scope:{'operator':operator,'scope':scope}
    operations=[
        ('create',principal,{'controller':principal,'keys':copy.deepcopy(record['keys']),'salt':fixture['salt'],'services':copy.deepcopy(record['services'])}),
        ('authorize-operator',principal,grant('activate')),
        ('activate',operator,{}),
        ('authorize-operator',principal,grant('update-services')),
        ('update-services',operator,{'services':fixture['rotated_services']}),
        ('add-key',principal,{'key':fixture['added']}),
        ('revoke-key',principal,{'name':'m-add'}),
        ('authorize-operator',principal,grant('deactivate')),
        ('revoke-operator',principal,grant('deactivate')),
        ('authorize-operator',principal,grant('deactivate')),
        ('revoke-operator',principal,grant('deactivate')),
        ('authorize-operator',principal,grant('deactivate')),
        ('revoke-key',principal,{'name':'z-sign'})if fixture['end_mode']=='last-signing-revoke'else('deactivate',operator,{}),
    ]
    for index,(operation,actor,arguments)in enumerate(operations,1):
        removals=[];target=None
        if operation=='authorize-operator':
            assert arguments not in grants;grants.append(copy.deepcopy(arguments));grants.sort(key=lambda x:(x['operator'],x['scope']));target=arguments
        elif operation=='revoke-operator':assert arguments in grants;grants.remove(arguments);target=arguments
        elif operation=='activate':
            record['state']='active';removals=[x for x in grants if x['scope']=='activate'];grants=[x for x in grants if x['scope']!='activate']
        elif operation=='deactivate':record['state']='deactivated';removals=copy.deepcopy(grants);grants=[]
        elif operation=='update-services':record['services']=copy.deepcopy(arguments['services'])
        elif operation=='add-key':record['keys'].append(copy.deepcopy(arguments['key']));record['keys'].sort(key=lambda x:x['name'])
        elif operation=='revoke-key':
            key=next(x for x in record['keys']if x['name']==arguments['name']);assert key['state']=='accepted';key['state']='revoked'
            if not any(x['alg']=='ed25519'and x['state']=='accepted'and('expires'not in x or x['expires']>fixture['admitted'][index-1])for x in record['keys']):
                record['state']='deactivated';removals=copy.deepcopy(grants);grants=[]
        record['version']=str(index)
        previous=str(index-1)if index>1 else''
        command={'actor':actor,'arguments':arguments,'binding':'sage-registry-chain-0.11.0','did':record['id'],'expectedVersion':previous,'operation':operation,'registry':registry}
        encoded_record=jcs(record);encoded_grants=jcs(grants);encoded_command=jcs(command)
        history={'actor':actor,'admitted':fixture['admitted'][index-1],'automaticRemovals':removals,'commandDigest':digest(encoded_command),'grantsDigest':digest(encoded_grants),'operation':operation,'previousVersion':previous,'recordDigest':digest(encoded_record),'target':target,'version':str(index)}
        result.append({'version':index,'operation':operation,'actor':actor,'record_hex':encoded_record.hex(),'grants_hex':encoded_grants.hex(),'command_hex':encoded_command.hex(),'history_hex':jcs(history).hex(),'command_digest_hex':hashlib.sha256(encoded_command).hexdigest(),'record_digest_hex':hashlib.sha256(encoded_record).hexdigest(),'grants_digest_hex':hashlib.sha256(encoded_grants).hexdigest(),'did_hash_hex':hashlib.sha256(record['id'].encode()).hexdigest()})
    assert len(result)==13 and record['state']=='deactivated'and not grants
    return result

if __name__=='__main__':
    print(json.dumps({'scope':'Independent expected bytes for one fixed ordinary owned13-mutation trace only','steps':expected_trace(json.load(sys.stdin))},separators=(',',':')))
