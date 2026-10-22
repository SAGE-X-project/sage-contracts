"""Read-only portable compiler evidence checker; no compiler, VM or network."""
from pathlib import Path
import hashlib,json,re,subprocess
root=Path(__file__).resolve().parent
repo=root.parents[3];evidence=root/'evidence/compiler'
digest=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
load=lambda p:json.loads(p.read_text())
prefix='ethereum/contracts/chain-registry/'
manifest=load(root/'source-identities.json');manifest_hash=digest(root/'source-identities.json')
assert manifest['scope']=='Bound Registry source and verification tools only; not operating qualification'
for section in ['source_files_sha256','tool_files_sha256']:
 for name,expected in manifest[section].items():
  p=repo/name;assert not Path(name).is_absolute() and '..' not in Path(name).parts and p.is_file() and not p.is_symlink();assert digest(p)==expected,name
assert manifest['tool_files_sha256'][str(Path(__file__).resolve().relative_to(repo))]==digest(Path(__file__))
assert len(manifest['source_files_sha256'])==32
derived={name:{'content':(repo/name).read_text()} for name in manifest['source_files_sha256'] if name.endswith('.sol')}
assert len(derived)==29 and all(name.startswith(prefix) for name in derived)
graph=load(evidence/'source-graph.json');complete=load(evidence/'compilation-complete.json')
assert complete=={'complete':True,'targets':['paris','shanghai'],'graph_size':29,'source_manifest_sha256':manifest_hash,'constructors_executed':False,'operating_ready':False}
assert graph['source_manifest_sha256']==manifest_hash and graph['exec_args']==['--max-old-space-size=512'] and re.fullmatch(r'v\d+\.\d+\.\d+',graph['node'])
compiler=root.parent/'evidence/soljson.cjs'
assert graph['compiler_sha256']==digest(compiler)=='5c509f760dc110a695c8b39bbc21e08c17dee431aa14d606f59e623d7c3cc657'
assert graph['sources_sha256']=={name:hashlib.sha256(value['content'].encode()).hexdigest() for name,value in derived.items()}
fixtures=root.parent/'fixtures';functions=load(fixtures/'functions.json');selectors=load(fixtures/'abi-selector-reference.json')['selectors']
normative=load(root/'fixtures/registry-management.json');reference=load(root/'fixtures/spec-reference.json')
assert reference['sha256']==digest(root/'fixtures/registry-management.json')
modules=load(root/'fixtures/expected-modules.json')
assert modules['compiler']=='0.8.20+commit.a1b79de6.Emscripten.clang' and set(modules['targets'])=={'paris','shanghai'}
literals=dict(re.findall(r'bytes32 private constant ([A-Z_]+)\s*=\s*bytes32\(0x([0-9a-f]{64})\);',derived[prefix+'RegistryRoleHashes.sol']['content']))
assert len(literals)==16 and all(int(value,16)>0 for value in literals.values())

def field(value):
    result = {'type': value['type']}
    if value['type'].startswith('tuple'):
        result['components'] = [field(child) for child in value['components']]
    return result


def method(value):
    return {'name': value['name'], 'stateMutability': value['stateMutability'],
            'inputs': [field(child) for child in value['inputs']], 'outputs': [field(child) for child in value['outputs']]}


def canonical(value):
    return '(' + ','.join(map(canonical, value['components'])) + ')' + value['type'][5:] if value['type'].startswith('tuple') else value['type']


def walk(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)


def scalar(type_):
    return {'type': type_}


def tuple_(components, array=False):
    return {'type': 'tuple[]' if array else 'tuple', 'components': components}


create = next(item for item in functions if item['name'] == 'revealClaim')
key_input = tuple_([field(item) for item in create['inputs'][2]['components']])
service_array = field(create['inputs'][3])
assert [item['type'] for item in key_input['components']] == ['string', 'string', 'bytes', 'string', 'bytes', 'bool', 'uint64']
assert [item['type'] for item in service_array['components']] == ['string', 'string', 'string']
grant_array = tuple_([scalar('address'), scalar('string')], True)
record_tuple = tuple_([scalar('string'), scalar('address'), tuple_([key_input, scalar('uint8')], True),
                       service_array, scalar('uint8'), scalar('uint64')])
snapshot_tuple = tuple_([record_tuple, grant_array, scalar('uint64')])
plan_tuple = tuple_([snapshot_tuple, *[scalar('bytes') for _ in range(5)], scalar('bytes32'), scalar('bool'),
                    scalar('uint64'), scalar('uint8'), scalar('bytes32'), scalar('address')])


def expected_method(name, mutability, inputs, outputs):
    return {'name': name, 'stateMutability': mutability, 'inputs': inputs, 'outputs': outputs}


expected_store = {
    'binding': expected_method('binding', 'view', [], [scalar('address'), scalar('uint256'), scalar('address')]),
    'claim': expected_method('claim', 'view', [scalar('address'), scalar('bytes32')], [scalar('bool'), scalar('bool'), scalar('uint256')]),
    'snapshot': expected_method('snapshot', 'view', [scalar('string')], [scalar('bool'), scalar('bool'), snapshot_tuple]),
    'commitClaim': expected_method('commitClaim', 'nonpayable', [scalar('address'), scalar('bytes32')], [scalar('uint256')]),
    'commit': expected_method('commit', 'nonpayable', [scalar('address'), scalar('string'), scalar('uint8'), scalar('bytes')],
                              [scalar('uint64'), scalar('bytes32'), scalar('bytes')]),
}
for name in ['record', 'activeGrants', 'historyItem']:
    expected_store[name] = method(next(item for item in functions if item['name'] == name))

# Closed ABI overapproximation from frozen public widths, not generated payloads.
limits = normative['limits']
dynamic_bytes = lambda size: 32 + ((size + 31) // 32) * 32
dynamic_array = lambda count, item_size: 32 + count * 32 + count * item_size
did_max = len('did:sage:eip155:') + 32 + 1 + 42 + 1 + limits['agent_id_bytes']
key_size = 7 * 32 + sum(dynamic_bytes(limits[name]) for name in [
    'key_name_bytes', 'algorithm_bytes', 'raw_key_bytes', 'signer_url_bytes', 'proof_bytes'])
stored_key_size = 2 * 32 + key_size
keys_size = dynamic_array(limits['lifetime_keys'], stored_key_size)
service_size = 3 * 32 + sum(dynamic_bytes(limits[name]) for name in ['key_name_bytes', 'service_type_bytes', 'service_uri_bytes'])
services_size = dynamic_array(limits['services'], service_size)
record_size = 6 * 32 + dynamic_bytes(did_max) + keys_size + services_size
# Every allowed scope is <=32 bytes. Its dynamic ABI tail is exactly64 bytes.
grant_size = 2 * 32 + dynamic_bytes(32)
grants_size = dynamic_array(limits['active_grants'], grant_size)
snapshot_size = 3 * 32 + record_size + grants_size
canonical_grants = 2 + limits['active_grants'] * 83 + limits['active_grants'] - 1
event_size = 8 * 32 + dynamic_bytes(did_max) + dynamic_bytes(len('authorize-operator'))
plan_size = 12 * 32 + snapshot_size + sum(dynamic_bytes(size) for size in [
    limits['record_bytes'], canonical_grants, limits['command_bytes'], limits['history_bytes'], event_size])
encoded_plan = 32 + plan_size
arithmetic = {'key_input': key_size, 'stored_key': stored_key_size, 'keys128': keys_size,
    'service': service_size, 'services16': services_size, 'record': record_size, 'grant': grant_size,
    'grants128': grants_size, 'current_snapshot': snapshot_size, 'snapshot_reply_bool_bool_struct': 3 * 32 + snapshot_size,
    'canonical_grant_pair': 83, 'canonical_grants128': canonical_grants,
    'transition_tuple': plan_size, 'abi_encode_transition': encoded_plan,
    'processor_bytes_return': 32 + dynamic_bytes(encoded_plan),
    'processor_call_actor_rawrequest': 4 + 2 * 32 + dynamic_bytes(limits['whole_calldata_bytes']),
    'store_commit_actor_agent_operation_plan': 4 + 4 * 32 + dynamic_bytes(limits['agent_id_bytes']) + dynamic_bytes(encoded_plan),
    'store_commit_return_version_didhash_eventbytes': 3 * 32 + dynamic_bytes(event_size),
    'history_two_bytes_return': 2 * 32 + dynamic_bytes(limits['history_bytes']) + dynamic_bytes(limits['command_bytes']),
    'record_bool_bytes_return': 2 * 32 + dynamic_bytes(limits['record_bytes']),
    'grants_bytes_return': 32 + dynamic_bytes(canonical_grants),
    'registryId_string_return': 32 + dynamic_bytes(len('eip155:') + 32 + 1 + 42), 'claim_three_scalars_reply': 3 * 32}
assert encoded_plan == 779424 and event_size == 512
assert all(size < 1048576 for size in arithmetic.values())
expected_structs = {
    'RegistryState.Snapshot': [('value', 'RegistryJson.Record'), ('grants', 'RegistryJson.Grant[]'), ('admitted', 'uint64')],
    'RegistryTransition.Plan': [('next','RegistryState.Snapshot'),('record','bytes'),('grants','bytes'),('command','bytes'),('history','bytes'),('eventData','bytes'),('claimDigest','bytes32'),('consumeClaim','bool'),('previousVersion','uint64'),('operation','RegistryJson.Operation'),('didHash','bytes32'),('actor','address')],
    'RegistryJson.Record': [('did', 'string'), ('controller', 'address'), ('keys', 'RegistryJson.Key[]'),
        ('services', 'IChainRegistry.ServiceInput[]'), ('state', 'RegistryJson.RecordState'), ('version', 'uint64')],
    'RegistryJson.Key': [('input', 'IChainRegistry.KeyInput'), ('state', 'RegistryJson.KeyState')],
    'RegistryJson.Grant': [('operator', 'address'), ('scope', 'string')],
    'IChainRegistry.KeyInput': list(zip(['name', 'alg', 'key', 'signer', 'proof', 'hasExpiry', 'expires'],
                                      [item['type'] for item in key_input['components']])),
    'IChainRegistry.ServiceInput': list(zip(['name', 'serviceType', 'uri'], [item['type'] for item in service_array['components']]))}
expected_enums = {'RegistryJson.Operation': ['Create', 'Activate', 'AddKey', 'RevokeKey', 'UpdateServices',
    'AuthorizeOperator', 'RevokeOperator', 'Deactivate'], 'RegistryJson.KeyState': ['Accepted', 'Revoked'],
    'RegistryJson.RecordState': ['Created', 'Active', 'Deactivated']}


roles = {'RENDERER': 'RegistryRenderer', 'VERIFIER': 'RegistryEd25519', 'RULES': 'RegistryRules', 'VALIDATOR': 'RegistryCallValidator',
         'STOREFACTORY': 'RegistryStoreFactory', 'CLAIMFACTORY': 'RegistryClaimProcessorFactory',
         'KEYFACTORY': 'RegistryKeyServiceProcessorFactory', 'LIFECYCLEFACTORY': 'RegistryLifecycleProcessorFactory'}
children = ['RegistryStore', 'RegistryClaimProcessor', 'RegistryKeyServiceProcessor', 'RegistryLifecycleProcessor']
expected_immutables = {'ChainRegistry': {'executionChain', 'instance', 'renderer', 'verifier', 'rules', 'validator', 'store',
    'claimProcessor', 'keyProcessor', 'lifecycleProcessor', 'rendererHash', 'verifierHash', 'rulesHash', 'validatorHash',
    'storeHash', 'claimHash', 'keyHash', 'lifecycleHash'}, 'RegistryStore': {'core', 'executionChain', 'instance'}}
for name in children[1:]:
    expected_immutables[name] = {'core', 'store', 'renderer', 'verifier', 'rules', 'executionChain', 'instance'}
primitive = root.parent / 'node_modules/@noble/hashes'
primitive_pins = {'package.json':'3e361734f5269de162fa362483d7f45dee7efb533ec217157945338f7591baaf',
    'sha3.js':'9a81e1edb24eae27b335533220167609cfb58008c5690e140ce478acdc669f32',
    '_u64.js':'b09da8c07fe8187c07649494cdb7cd0bcf13df90b506a9473d19e4d5f8c2e102',
    'utils.js':'037ad49adb78168b6b699598fd33f85f7877456b1d28b4d032e2a1a16807947c'}
assert graph['primitive_sha256'] == primitive_pins
for name, expected in primitive_pins.items(): assert digest(primitive/name) == expected
hash_inputs = { 'source:' + name: value['content'].encode().hex() for name, value in derived.items() }
metadata_sources = []
hash_candidates = {}
expected_files = {'source-graph.json', 'compilation-complete.json', 'role-hashes.json'}
for target in ['paris', 'shanghai']:
    expected_files.update(target + '-' + ending + '.json' for ending in ['input', 'output', 'sizes'])
    input_ = load(evidence / (target + '-input.json'))
    output = load(evidence / (target + '-output.json'))
    sizes = load(evidence / (target + '-sizes.json'))['rows']
    assert input_ == {'language': 'Solidity', 'sources': derived, 'settings': {'optimizer': {'enabled': True, 'runs': 200},
        'viaIR': True, 'evmVersion': target, 'metadata': {'bytecodeHash': 'ipfs', 'appendCBOR': True},
        'outputSelection': {'*': {'*': ['abi', 'metadata', 'storageLayout', 'evm.bytecode', 'evm.deployedBytecode', 'evm.methodIdentifiers'], '': ['ast']}}}}
    assert set(output['sources']) == set(derived) and not [item for item in output.get('errors', []) if item['severity'] == 'error']
    for file, contracts in output['contracts'].items():
        for name, artifact in contracts.items():
            metadata = json.loads(artifact['metadata'])
            assert metadata['compiler'] == {'version': '0.8.20+commit.a1b79de6'}
            assert metadata['language'] == 'Solidity'
            assert metadata['settings'] == {'compilationTarget': {file: name}, 'evmVersion': target, 'libraries': {},
                'metadata': {'bytecodeHash': 'ipfs'}, 'optimizer': {'enabled': True, 'runs': 200}, 'remappings': [], 'viaIR': True}
            assert set(metadata['sources']) <= set(derived) and file in metadata['sources']
            metadata_sources.extend((source_name, value['keccak256']) for source_name, value in metadata['sources'].items())

    nodes = {item['id']: item for value in output['sources'].values() for item in walk(value['ast']) if 'id' in item and 'nodeType' in item}
    definitions = {item['canonicalName']: item for item in nodes.values() if item['nodeType'] in ['StructDefinition', 'EnumDefinition']}

    def ast_type(node):
        if node['nodeType'] == 'ElementaryTypeName':
            return node['name']
        if node['nodeType'] == 'ArrayTypeName':
            # Solc0.8.20 omits this key for dynamic arrays; explicit null is also
            # dynamic. Every actual fixed-size expression remains a refusal.
            assert node.get('length') is None
            return ast_type(node['baseType']) + '[]'
        assert node['nodeType'] == 'UserDefinedTypeName'
        return nodes[node['referencedDeclaration']]['canonicalName']

    def ast_abi(node):
        if node['nodeType'] == 'ElementaryTypeName':
            return scalar(node['name'])
        if node['nodeType'] == 'ArrayTypeName':
            assert node.get('length') is None
            item = ast_abi(node['baseType'])
            return {**item, 'type': item['type'] + '[]'}
        assert node['nodeType'] == 'UserDefinedTypeName'
        definition = nodes[node['referencedDeclaration']]
        if definition['nodeType'] == 'EnumDefinition':
            assert len(definition['members']) <= 256
            return scalar('uint8')
        assert definition['nodeType'] == 'StructDefinition'
        return tuple_([ast_abi(member['typeName']) for member in definition['members']])

    for name, members in expected_structs.items():
        assert [(item['name'], ast_type(item['typeName'])) for item in definitions[name]['members']] == members
    for name, members in expected_enums.items():
        assert [item['name'] for item in definitions[name]['members']] == members
    assert tuple_([ast_abi(item['typeName']) for item in definitions['RegistryState.Snapshot']['members']]) == snapshot_tuple
    assert tuple_([ast_abi(item['typeName']) for item in definitions['RegistryTransition.Plan']['members']]) == plan_tuple
    artifacts = {name: (file, value) for file, values in output['contracts'].items() for name, value in values.items()
                 if value['evm']['deployedBytecode']['object'] or value['evm']['bytecode']['object']}
    assert set(sizes) == set(artifacts) and {'ChainRegistry', *roles.values(), *children} <= set(artifacts)
    for name, (file, artifact) in artifacts.items():
        runtime, creation = artifact['evm']['deployedBytecode'], artifact['evm']['bytecode']
        code, init = runtime['object'], creation['object']
        assert re.fullmatch(r'(?:[0-9a-f]{2})+', code) and re.fullmatch(r'(?:[0-9a-f]{2})+', init)
        assert not runtime['linkReferences'] and not creation['linkReferences']
        constructor = next((item for item in artifact['abi'] if item['type'] == 'constructor'), {'inputs': []})
        assert all(item['type'] == 'address' for item in constructor['inputs'])
        args = len(constructor['inputs']) * 32
        row = sizes[name]
        assert row['source'] == file and row['runtime_bytes'] == len(code) // 2 and row['creation_bytes'] == len(init) // 2
        assert row['constructor_args_bytes'] == args and row['total_initcode_bytes'] == len(init) // 2 + args
        assert row['runtime_sha256'] == hashlib.sha256(bytes.fromhex(code)).hexdigest()
        assert row['creation_sha256'] == hashlib.sha256(bytes.fromhex(init)).hexdigest()
        assert row['immutable_references'] == runtime['immutableReferences']
        assert row['EIP170_within'] == (len(code) // 2 <= 24576) and row['EIP3860_within'] == (len(init) // 2 + args <= 49152)
        assert row['constructor_not_executed'] is True
        assert row['EIP170_within'] and row['EIP3860_within']
        if name in roles.values():
            assert artifact['storageLayout']['storage'] == [], 'Stateless role contains mutable storage: ' + name
        inherited_nodes = list(walk(output['sources'][file]['ast']))
        if name in children[1:]:
            inherited_nodes += list(walk(output['sources'][prefix + 'RegistryProcessor.sol']['ast']))
        immutables = {str(item['id']): item['name'] for item in inherited_nodes
                      if item.get('nodeType') == 'VariableDeclaration' and item.get('mutability') == 'immutable'}
        assert set(immutables) == set(runtime['immutableReferences'])
        assert set(immutables.values()) == expected_immutables.get(name, set())
        for spans in runtime['immutableReferences'].values():
            assert spans and all(span['length'] == 32 and 0 <= span['start'] <= len(code) // 2 - 32 for span in spans)
        hash_inputs[target + ':' + name] = code
        if name in roles.values():
            role = next(role for role, subject in roles.items() if subject == name)
            hash_candidates[target.upper() + '_' + role] = row['runtime_keccak256']
            baseline = modules['targets'][target][role]
            assert baseline['contract'] == name
            assert hashlib.sha256(bytes.fromhex(code)).hexdigest() == baseline['runtime_sha256']
            assert hashlib.sha256(bytes.fromhex(init)).hexdigest() == baseline['creation_sha256']
            assert row['runtime_keccak256'] == baseline['runtime_keccak256'] == literals[target.upper()+'_'+role]
    chain = artifacts['ChainRegistry'][1]
    abi = chain['abi']
    actual = [item for item in abi if item['type'] == 'function']
    assert len(actual) == 13 and {item['name']: method(item) for item in actual} == {item['name']: method(item) for item in functions}
    assert chain['evm']['methodIdentifiers'] == {item['name'] + '(' + ','.join(map(canonical, item['inputs'])) + ')':
        selectors[item['name']].removeprefix('0x') for item in functions}
    errors = [item for item in abi if item['type'] == 'error']
    assert len(errors) == 22 and {item['name'] for item in errors} == set(normative['errors']) and all(not item['inputs'] for item in errors)
    events = [item for item in abi if item['type'] == 'event']
    assert len(events) == 2 and {item['name'] for item in events} == set(normative['events'])
    for item in events:
        norm = normative['events'][item['name']]
        assert item['anonymous'] is False and item['name'] + '(' + ','.join(map(canonical, item['inputs'])) + ')' == norm['signature']
        assert [child['name'] + ':' + child['type'] + ':' + ('topic' if child['indexed'] else 'data') for child in item['inputs']] == norm['layout']
    assert sorted(item['type'] for item in abi if item['type'] not in ['function', 'event', 'error']) == ['constructor', 'fallback']
    assert next(item for item in abi if item['type'] == 'fallback') == {'type': 'fallback', 'stateMutability': 'payable'}
    assert len(next(item for item in abi if item['type'] == 'constructor')['inputs']) == 8
    assert [(item['label'], item['slot'], item['offset']) for item in chain['storageLayout']['storage']] == [('identity', '0', 0)]
    store = artifacts['RegistryStore'][1]
    assert [(item['label'], item['slot'], item['offset']) for item in store['storageLayout']['storage']] == [
        ('identity', '0', 0), ('claims', '1', 0), ('records', '2', 0)]
    store_methods = [item for item in store['abi'] if item['type'] == 'function']
    assert len(store_methods) == len({item['name'] for item in store_methods}) == 8
    assert {item['name']: method(item) for item in store_methods} == expected_store
    assert not [item for item in store['abi'] if item['type'] == 'event']
    for name in children[1:]:
        child = artifacts[name][1]
        methods = [item for item in child['abi'] if item['type'] == 'function']
        assert {item['name'] for item in methods} == {'binding', 'prepare'} and all(item['stateMutability'] == 'view' for item in methods)
        assert not [item for item in child['abi'] if item['type'] == 'event']
    for name in [role for role in roles.values() if role.endswith('Factory')]:
        factory = artifacts[name][1]
        assert len([item for item in factory['abi'] if item['type'] == 'function']) == 1
        assert next(item for item in factory['abi'] if item['type'] == 'function')['name'] == 'create'

# Only the pinned four-file Keccak primitive is imported; no project/VM module.
script = """import fs from 'node:fs';const {keccak_256}=await import(process.argv[1]);
const values=JSON.parse(fs.readFileSync(0,'utf8'));process.stdout.write(JSON.stringify(Object.fromEntries(
Object.entries(values).map(([name,code])=>[name,Buffer.from(keccak_256(Buffer.from(code,'hex'))).toString('hex')]))));"""
actual_hashes = json.loads(subprocess.check_output(['node', '--max-old-space-size=512', '--input-type=module', '-e', script,
    (primitive / 'sha3.js').as_uri()], input=json.dumps(hash_inputs), text=True))
for target in ['paris', 'shanghai']:
    rows = load(evidence / (target + '-sizes.json'))['rows']
    for name, row in rows.items():
        assert actual_hashes[target + ':' + name] == row['runtime_keccak256']
for name, expected in metadata_sources:
    assert '0x' + actual_hashes['source:' + name] == expected
candidate = load(evidence / 'role-hashes.json')
assert candidate == {'hashes':hash_candidates,'byte_identical_role_digests':16,'source_manifest_sha256':manifest_hash}
assert hash_candidates == literals and len(hash_candidates)==16
assert {path.name for path in evidence.iterdir()} == expected_files and all(path.is_file() and not path.is_symlink() for path in evidence.iterdir())
print(json.dumps({'verified':True,'targets':['paris','shanghai'],'sources':29,'bound_role_digest_joins':16,
    'source_manifest_sha256':manifest_hash,'abi_maximum_calculations':arithmetic,
    'evidence_files_sha256':{name:hashlib.sha256((evidence/name).read_bytes()).hexdigest() for name in sorted(expected_files)},
    'scope':'Compiler full graph/metadata/ABI/schema/layout/digests/sizes only; no constructors/runtime/coverage/Source or operating qualification',
    'constructors_executed':False,'operating_ready':False}))
