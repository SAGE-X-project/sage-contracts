"""Pure source-range bookkeeping. No execution, imports of project code or I/O."""
import base64
import hashlib

STATEMENTS = frozenset(['Break', 'Continue', 'DoWhileStatement', 'EmitStatement',
    'ExpressionStatement', 'ForStatement', 'IfStatement', 'InlineAssembly',
    'Return', 'RevertStatement', 'TryStatement', 'VariableDeclarationStatement', 'WhileStatement'])

def source_hash(text):
    return hashlib.sha256(text.encode('utf8')).hexdigest()

def canonical_statements(source_name, content, ast):
    result = []
    digest = source_hash(content)
    def walk(node, contract='', function=''):
        if isinstance(node, list):
            for child in node:
                walk(child, contract, function)
            return
        if not isinstance(node, dict):
            return
        kind = node.get('nodeType')
        if kind == 'ContractDefinition':
            contract = node['name']
        if kind == 'FunctionDefinition':
            function = node.get('name') or '<' + node['kind'] + '>'
        if kind in STATEMENTS:
            start, length, local_file = map(int, node['src'].split(':'))
            if start < 0 or length <= 0 or start + length > len(content.encode('utf8')):
                raise ValueError('Invalid canonical statement range')
            result.append({'source': source_name, 'source_sha256': digest,
                'type': kind, 'start': start, 'length': length,
                'canonical_local_ast_id': node['id'], 'canonical_local_file_id': local_file,
                'contract': contract, 'function': function})
        for child in node.values():
            if isinstance(child, (dict, list)):
                walk(child, contract, function)
    walk(ast)
    keys = [(x['type'], x['start'], x['length']) for x in result]
    if len(keys) != len(set(keys)):
        raise ValueError('Ambiguous canonical statement identity')
    return result

def code_limit(kind):
    if kind not in ['creation', 'runtime']:
        raise ValueError('Unknown bytecode namespace')
    return 49152 if kind == 'creation' else 24576

def instruction_maps(code_hex, source_map, kind='runtime'):
    code = bytes.fromhex(code_hex)
    if not code or len(code) > code_limit(kind):
        raise ValueError('Bytecode outside fixed runtime bound')
    positions = []
    pc = 0
    while pc < len(code):
        positions.append(pc)
        opcode = code[pc]
        # EVM pads a final truncated PUSH operand with zero; metadata may also
        # contain arbitrary bytes. Neither creates operand-byte instructions.
        pc += 1 + (opcode - 0x5f if 0x60 <= opcode <= 0x7f else 0)
    entries = []
    previous = ['-1', '-1', '-1', '', '0']
    for encoded in source_map.split(';'):
        fields = encoded.split(':')
        if len(fields) > 5:
            raise ValueError('Malformed source map')
        row = list(previous)
        for index, value in enumerate(fields):
            if value:
                row[index] = value
        start, length, source_id = map(int, row[:3])
        if start < -1 or length < -1 or source_id < -1:
            raise ValueError('Malformed source coordinates')
        entries.append((start, length, source_id))
        previous = row
    if len(entries) > len(positions):
        raise ValueError('Source map exceeds instruction count')
    return {pc: entries[index] if index < len(entries) else None
            for index, pc in enumerate(positions)}

def mapped_spans(code_hex, source_map, visited, kind='runtime'):
    if not isinstance(visited, list) or any(type(pc) is not int for pc in visited):
        raise ValueError('PC list must contain integers')
    if visited != sorted(set(visited)) or len(visited) > code_limit(kind):
        raise ValueError('PC list must be bounded, unique and ordered')
    maps = instruction_maps(code_hex, source_map, kind)
    result = []
    classes = {'unmapped': 0, 'generated_or_unknown': 0, 'zero_length': 0, 'mapped': 0}
    for pc in visited:
        if pc not in maps:
            raise ValueError('Visited PC is not an instruction boundary')
        entry = maps[pc]
        if entry is None:
            classes['unmapped'] += 1
        elif entry[0] < 0 or entry[1] < 0 or entry[2] < 0:
            classes['generated_or_unknown'] += 1
        elif entry[1] == 0:
            classes['zero_length'] += 1
        else:
            classes['mapped'] += 1
            result.append({'pc': pc, 'start': entry[0], 'length': entry[1], 'file': entry[2]})
    return result, classes

def contained(statement, span, actual_source_sha256):
    return (actual_source_sha256 == statement['source_sha256']
        and span['length'] > 0 and statement['start'] <= span['start']
        and span['start'] + span['length'] <= statement['start'] + statement['length'])

def join_witnesses(statements, spans, local_sources, context):
    by_hash = {}
    for statement in statements:
        by_hash.setdefault(statement['source_sha256'], set()).add(statement['source'])
    witnesses = {}
    foreign = 0
    for span in spans:
        source = local_sources.get(span['file'])
        if source is None:
            foreign += 1
            continue
        digest = source_hash(source['content'])
        candidates = by_hash.get(digest, set())
        if len(candidates) > 1:
            raise ValueError('Source hash names multiple canonical source identities')
        if not candidates:
            foreign += 1
            continue
        if span['start'] + span['length'] > len(source['content'].encode('utf8')):
            raise ValueError('Mapped range outside source bytes')
        for index, statement in enumerate(statements):
            if contained(statement, span, digest):
                witnesses.setdefault(index, {'context': context, 'pc': span['pc'],
                    'mapped_start': span['start'], 'mapped_length': span['length'],
                    'build_local_source_id': span['file'], 'source_sha256': digest})
    return witnesses, foreign

def bitmap_pcs(encoded, code_hex, kind='runtime'):
    if type(encoded) is not str or len(encoded) > 4 * ((code_limit(kind) + 23) // 24):
        raise ValueError('Bitmap encoding outside fixed bound')
    try:
        data = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError):
        raise ValueError('Invalid bitmap encoding') from None
    if base64.b64encode(data).decode('ascii') != encoded:
        raise ValueError('Noncanonical bitmap encoding')
    code = bytes.fromhex(code_hex)
    maps = instruction_maps(code_hex, '', kind)
    if len(data) != (len(code) + 7) // 8:
        raise ValueError('Bitmap width differs from bytecode')
    if len(code) % 8 and data[-1] >> (len(code) % 8):
        raise ValueError('Bitmap has bits beyond bytecode')
    pcs = []
    for byte_index, value in enumerate(data):
        for bit in range(8):
            if value & (1 << bit):
                pc = byte_index * 8 + bit
                if pc not in maps:
                    raise ValueError('Bitmap selected a PUSH operand')
                pcs.append(pc)
    return pcs
