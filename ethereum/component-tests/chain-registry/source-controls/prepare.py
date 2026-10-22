"""Prepare finite local compiler/VM subjects from the checked-out original sources."""
import os, sys
if sys.flags.optimize != 0 or os.environ.get('PYTHONOPTIMIZE', '') not in ('', '0'):
    raise RuntimeError('Optimized Python is not permitted')

from pathlib import Path
import copy
import hashlib
import json
from core_identity import expected_runtime, immutable_names
from pilot_source_ranges import canonical_statements
from source_probe import instrument_source

HERE = Path(__file__).resolve().parent
BASE = HERE.parent
REPO = BASE.parents[2]
OUT = HERE / 'evidence'
PREFIX = 'ethereum/contracts/chain-registry/'
ROLES = ['RegistryRenderer', 'RegistryEd25519', 'RegistryRules', 'RegistryCallValidator',
         'RegistryStoreFactory', 'RegistryClaimProcessorFactory',
         'RegistryKeyServiceProcessorFactory', 'RegistryLifecycleProcessorFactory']
sha = lambda value: hashlib.sha256(value).hexdigest()

def read(path):
    assert path.is_file() and not path.is_symlink()
    return json.loads(path.read_text())

def write(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')

def original(profile):
    folder = BASE / 'runtime/evidence/compiler'
    inp, output = [read(folder / (profile + '-' + suffix + '.json')) for suffix in ['input', 'output']]
    assert inp['settings']['evmVersion'] == profile and len(inp['sources']) == len(output['sources']) == 29
    assert not any(error['severity'] == 'error' for error in output.get('errors', []))
    for name, item in inp['sources'].items():
        path = REPO / name
        assert path.is_file() and not path.is_symlink() and path.read_bytes() == item['content'].encode()
    return inp, output

def artifact(output, name, wrapper=False):
    path = ('ethereum/component-tests/chain-registry/' if wrapper else PREFIX) + name + '.sol'
    return output['contracts'][path][name]

def images(art, names=None, words=None):
    assert not art['evm']['bytecode'].get('linkReferences')
    deployed = art['evm']['deployedBytecode']
    assert not deployed.get('linkReferences')
    if words is None:
        assert not deployed.get('immutableReferences')
        runtime = deployed['object']
    else:
        runtime = expected_runtime(deployed, names, words)['hex']
    result = {}
    for kind, value, cap in [('creation', art['evm']['bytecode']['object'], 49152), ('runtime', runtime, 24576)]:
        raw = bytes.fromhex(value)
        assert 0 < len(raw) <= cap
        result[kind] = {'hex': value, 'bytes': len(raw), 'sha256': sha(raw)}
    return result

def inputs():
    assert not OUT.exists(), 'Preserve previous evidence; use a fresh checkout for a retry'
    OUT.mkdir()
    inp, output = original('shanghai')
    paris, _ = original('paris')
    assert inp['sources'] == paris['sources']
    catalogue = [row for name, item in inp['sources'].items()
                 for row in canonical_statements(name, item['content'], output['sources'][name]['ast'])]
    assert len(catalogue) == 1642
    write(OUT / 'catalogue.json', catalogue)
    profiles = read(HERE / 'compiler-profiles.json')['profiles']
    selections = {
        'stateless': [PREFIX + name + '.sol' for name in ['RegistryRenderer', 'RegistryCallValidator']],
        'rules': [PREFIX + 'RegistryRules.sol'],
        'processor': ['ethereum/component-tests/chain-registry/ProcessorPureControls.sol'],
        'semantic': ['ethereum/component-tests/chain-registry/SemanticHelperControls.sol'],
        'core': [PREFIX + 'ChainRegistry.sol'],
    }
    transform = {'scope': 'Test-only statement probes; original source identities retained', 'sources': {}}
    for name, item in inp['sources'].items():
        transform['sources'][name] = instrument_source(item['content'], output['sources'][name]['ast'],
            [row for row in catalogue if row['source'] == name], output['sources'][name]['id'])
    write(OUT / 'whole-source-transformation.json', transform)
    builds = []
    for group, selected in selections.items():
        for fork in (['paris', 'shanghai'] if group in ['stateless', 'rules'] else ['shanghai']):
            sources = copy.deepcopy(inp['sources'])
            if group in ['processor', 'semantic']:
                name = selected[0]
                sources[name] = {'content': (HERE / Path(name).name).read_text()}
            if group == 'core':
                sources = {name: {'content': value['content']} for name, value in transform['sources'].items()}
            settings = copy.deepcopy(profiles['product' if group == 'core' else group])
            settings.update(evmVersion=fork, outputSelection={name: {'*': ['abi', 'evm.bytecode', 'evm.deployedBytecode', 'evm.methodIdentifiers']} for name in selected})
            settings['outputSelection']['*'] = {'': ['ast']}
            build = group + '-' + fork
            write(OUT / (build + '-input.json'), {'language': 'Solidity', 'sources': sources, 'settings': settings})
            builds.append({'id': build, 'selected': selected, 'profile': fork, 'timeout': 600 if group == 'core' else 180})
    write(OUT / 'builds.json', builds)
    return builds

def subjects():
    original_input, product = original('shanghai')
    binding = read(HERE / 'fixtures/normal-bindings.json')
    compiler = lambda group, fork: read(OUT / (group + '-' + fork + '-output.json'))
    parts = []
    for group in ['stateless', 'rules']:
        cases = read(HERE / ('fixtures/' + group + '.json'))['cases']
        for fork in ['paris', 'shanghai']:
            _, prod = original(fork)
            control = compiler(group, fork)
            modules = []
            for build, compiled in [('product', prod), ('control', control)]:
                names = ['RegistryRenderer', 'RegistryCallValidator'] if group == 'stateless' else ['RegistryRules']
                for name in names:
                    modules.append({'id': build + '-' + name, 'contract': name, 'build': build,
                        'compiler': group + '-' + fork if build == 'control' else 'product-' + fork,
                        'images': images(artifact(compiled, name))})
            calls = [{**row, 'name': row.get('name', row['method']), 'module_id': module['id'], 'observe': module['build'] == 'control'}
                     for module in modules for row in cases if row['subject'] == module['contract']]
            parts.append({'id': group + '-' + fork, 'profile': fork, 'caller': '0x0000000000000000000000000000000000001000',
                          'modules': modules, 'deployments': [{'id': m['id'], 'data': m['images']['creation']['hex']} for m in modules],
                          'calls': calls, 'setup': [], 'expected_calls': 38 if group == 'stateless' else 252})
    core_calls = read(HERE / 'fixtures/core-reads.json')
    for group in ['processor', 'core']:
        modules, deployments = [], []
        compiled = compiler(group, 'shanghai')
        all_names = ROLES + ['RegistryStore', 'RegistryClaimProcessor', 'RegistryKeyServiceProcessor', 'RegistryLifecycleProcessor', 'ChainRegistry']
        for name in all_names:
            chosen = compiled if group == 'core' and name == 'ChainRegistry' else product
            art = artifact(chosen, name)
            words = binding['modules'][name]['words']
            modules.append({'id': name, 'contract': name, 'address': binding['modules'][name]['address'],
                'compiler': 'core-shanghai' if chosen is compiled else 'product-shanghai',
                'instrumented': chosen is compiled, 'images': images(art, immutable_names(chosen['sources']), words)})
        for name in ROLES + ['ChainRegistry']:
            module = next(m for m in modules if m['id'] == name)
            args = ''.join(binding['modules'][n]['address'][2:].rjust(64, '0') for n in ROLES) if name == 'ChainRegistry' else ''
            deployments.append({'id': name, 'data': module['images']['creation']['hex'] + args, 'expected_address': module['address']})
        if group == 'processor':
            address = '0x44c3a8570619fef571cae93276261f89e7c61165'
            names = dict(core='ChainRegistry', store='RegistryStore', renderer='RegistryRenderer', verifier='RegistryEd25519', rules='RegistryRules')
            words = {k: binding['modules'][v]['address'][2:].rjust(64, '0') for k, v in names.items()}
            words.update(executionChain=f'{1:064x}', instance=address[2:].rjust(64, '0'))
            art = artifact(compiled, 'ProcessorPureControls', True)
            module = {'id': 'ProcessorPureControls', 'contract': 'ProcessorPureControls', 'address': address,
                      'compiler': 'processor-shanghai', 'images': images(art, immutable_names(compiled['sources']), words)}
            modules.append(module)
            deployments.append({'id': module['id'], 'data': module['images']['creation']['hex'] + ''.join(words[k] for k in names), 'expected_address': address})
            calls = [{**row, 'module_id': module['id'], 'observe': True} for row in read(HERE / 'fixtures/processor.json')['cases']]
        else:
            calls = [{**row, 'module_id': 'ChainRegistry', 'observe': True} for row in core_calls['queries']]
        parts.append({'id': group + '-shanghai', 'profile': 'shanghai', 'caller': binding['caller'], 'modules': modules,
            'deployments': deployments, 'calls': calls, 'setup': core_calls['setup'] if group == 'core' else [],
            'expected_calls': 46 if group == 'processor' else 2})
    compiled = compiler('semantic', 'shanghai')
    modules = []
    for fork in ['shanghai', 'paris']:
        _, prod = original(fork)
        modules.extend({'id': fork + '-' + name, 'contract': name, 'compiler': 'product-' + fork,
                        'images': images(artifact(prod, name))} for name in ROLES)
    modules.append({'id': 'SemanticHelperControls', 'contract': 'SemanticHelperControls', 'compiler': 'semantic-shanghai',
                    'images': images(artifact(compiled, 'SemanticHelperControls', True))})
    art = artifact(compiled, 'SemanticHelperControls', True)
    role_selector = art['evm']['methodIdentifiers']['acceptsRoles(' + ','.join(['address'] * 8) + ')']
    parts.append({'id': 'semantic-shanghai', 'profile': 'shanghai', 'caller': '0x0000000000000000000000000000000000001000',
                  'modules': modules, 'deployments': [{'id': m['id'], 'data': m['images']['creation']['hex']} for m in modules],
                  'calls': [{**row, 'module_id': 'SemanticHelperControls', 'observe': True} for row in read(HERE / 'fixtures/semantic.json')['cases']],
                  'setup': [], 'role_selector': role_selector, 'role_names': ROLES, 'expected_calls': 29})
    assert len(parts) == 7
    for part in parts:
        assert all(len(bytes.fromhex(d['data'])) <= 49152 for d in part['deployments'])
    write(OUT / 'subjects.json', {'scope': 'Finite positive local VM tests only; operating connection not configured', 'parts': parts})

if __name__ == '__main__':
    import sys
    if sys.argv[1] == 'inputs': inputs()
    else:
        assert sys.argv[1] == 'subjects'
        subjects()
