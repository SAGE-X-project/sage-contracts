import base64
import copy
import unittest
from core_identity import code_bytes, immutable_names, expected_runtime, visited_pcs, contained_hits

class IdentityUnits(unittest.TestCase):
    def setUp(self):
        self.sources = {'A.sol': {'ast': {'nodes': [{'nodeType': 'VariableDeclaration', 'mutability': 'immutable', 'id': 7, 'name': 'core'}, {'nodeType':'VariableDeclaration','mutability':'constant','id':8,'name':'other'}]}}}
        self.image = {'object': '7f' + '00'*32 + '00', 'immutableReferences': {'7': [{'start':1,'length':32}]}, 'linkReferences': {}}
        self.names = {'7':'core'}
        self.words = {'core':'00'*31+'01'}
        self.marker = '7f'+'12'*31
        self.code = '7f'+self.marker+'00'
        self.row = {'marker_hex':self.marker,'source':'A.sol','probe_start':10,'probe_length':100}
    def test_named_ast_and_expected_bytes(self):
        names=immutable_names(self.sources)
        self.assertEqual(names,self.names)
        result=expected_runtime(self.image,names,self.words)
        self.assertEqual(result['hex'],'7f'+self.words['core']+'00')
        self.assertEqual(result['immutable_ids'],1)
    def test_no_immutable_and_shared_occurrences(self):
        self.assertEqual(expected_runtime({'object':'00'}, {}, {})['hex'],'00')
        self.image['object']='7f'+'00'*32+'7f'+'00'*32+'00'
        self.image['immutableReferences']['7'].append({'start':34,'length':32})
        self.assertEqual(len(expected_runtime(self.image,self.names,self.words)['immutable_bindings'][0]['positions']),2)
    def test_ast_duplicate_id(self):
        self.sources['A.sol']['ast']['nodes'].append(copy.deepcopy(self.sources['A.sol']['ast']['nodes'][0]))
        with self.assertRaises(AssertionError): immutable_names(self.sources)
    def test_ast_invalid_id_and_empty_name(self):
        for field,value in [('id',True),('name','')]:
            data=copy.deepcopy(self.sources);data['A.sol']['ast']['nodes'][0][field]=value
            with self.assertRaises(AssertionError): immutable_names(data)
    def test_unknown_immutable_id(self):
        with self.assertRaises(AssertionError): expected_runtime(self.image,{},self.words)
    def test_duplicate_names(self):
        self.image['immutableReferences']['8']=[{'start':1,'length':32}]
        with self.assertRaises(AssertionError): expected_runtime(self.image,{'7':'core','8':'core'},self.words)
    def test_missing_extra_or_invalid_words(self):
        for words in [{},{'core':self.words['core'],'extra':'00'*32},{'core':'AA'*32},{'core':'01'}]:
            with self.assertRaises(AssertionError): expected_runtime(self.image,self.names,words)
    def test_link_references_rejected(self):
        self.image['linkReferences']={'lib':{}}
        with self.assertRaises(AssertionError): expected_runtime(self.image,self.names,self.words)
    def test_bad_immutable_interval(self):
        for positions in [[],[{'start':True,'length':32}],[{'start':1,'length':31}],[{'start':-1,'length':32}],[{'start':3,'length':32}],[{'start':1,'length':32,'extra':1}]]:
            image=copy.deepcopy(self.image);image['immutableReferences']['7']=positions
            with self.assertRaises(AssertionError): expected_runtime(image,self.names,self.words)
    def test_overlap_is_rejected(self):
        self.image['immutableReferences']['7'].append({'start':1,'length':32})
        with self.assertRaises(AssertionError): expected_runtime(self.image,self.names,self.words)
    def test_nonzero_placeholder_rejected(self):
        self.image['object']='7f'+'01'*32+'00'
        with self.assertRaises(AssertionError): expected_runtime(self.image,self.names,self.words)
    def test_bad_code_and_size(self):
        for value in ['', 'a', 'AA', 'gg', '00'*24577]:
            with self.assertRaises(AssertionError): code_bytes(value)
    def test_visited_opcode_positions(self):
        self.assertEqual(visited_pcs(self.code,base64.b64encode(bytes([1,0,0,0,2])).decode()),{0,33})
        self.assertEqual(visited_pcs('00','AA=='),set())
    def test_visited_operand_and_padding_rejected(self):
        for value in [bytes([2,0,0,0,0]),bytes([0,0,0,0,4])]:
            with self.assertRaises(AssertionError): visited_pcs(self.code,base64.b64encode(value).decode())
    def test_bitmap_encoding_and_width_rejected(self):
        for value in ['@@', 'AA==\n', '', 'AAA=']:
            with self.assertRaises((AssertionError,ValueError)): visited_pcs('00',value)
    def test_contained_and_absent_hits(self):
        spans={0:(12,20,0),33:None}
        self.assertEqual(len(contained_hits(self.code,spans,{'A.sol':0},[self.row],{0,33})),1)
        self.assertEqual(contained_hits(self.code,spans,{'A.sol':0},[self.row],set()),[])
    def test_non_marker_and_wrong_marker_no_credit(self):
        self.assertEqual(contained_hits('00',{0:(12,20,0)},{'A.sol':0},[self.row],{0}),[])
        self.assertEqual(contained_hits('7f'+'34'*32,{0:(12,20,0)},{'A.sol':0},[self.row],{0}),[])
    def test_unmapped_and_uncontained_no_credit(self):
        for span in [None,(12,0,0),(12,20,1),(9,20,0),(12,99,0)]:
            self.assertEqual(contained_hits(self.code,{0:span},{'A.sol':0},[self.row],{0}),[])
    def test_source_id_and_duplicate_marker_rejected(self):
        with self.assertRaises(AssertionError): contained_hits(self.code,{0:(12,20,0)},{'A.sol':0,'B.sol':0},[self.row],{0})
        with self.assertRaises(AssertionError): contained_hits(self.code,{0:(12,20,0)},{'A.sol':0},[self.row,self.row],{0})
    def test_invalid_probe_data_rejected(self):
        for changes in [{'marker_hex':'00'*32},{'source':'B.sol'},{'probe_start':True},{'probe_length':0}]:
            row={**self.row,**changes}
            with self.assertRaises(AssertionError): contained_hits(self.code,{0:(12,20,0)},{'A.sol':0},[row],{0})
    def test_unknown_pc_rejected(self):
        with self.assertRaises(AssertionError): contained_hits(self.code,{0:(12,20,0)},{'A.sol':0},[self.row],{1})
