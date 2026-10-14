from support import WORKSPACE
"""Raw YARA VEX wildcard hits are clues until executable decoding validates them."""
from pathlib import Path
import unittest
from unittest.mock import patch
from qcs.yara_engine import aes_instruction_offsets
from qcs.scanner import scan, Options
from qcs.model import predictions

class YaraInstructionTests(unittest.TestCase):
 def test_invalid_vex_constants_and_immediate_payloads_are_not_instructions(self):
  # Valid AES bytes are embedded as a MOV's immediate, and separately in data.
  raw=bytes.fromhex('48b8660f38dcc0000000c3')
  regions=[(4096,100,raw,1),(8192,200,bytes.fromhex('660f38dcc0'),0)]
  with patch('qcs.function_signatures.function_regions',return_value=(regions,['x86_64'])):
   self.assertEqual(aes_instruction_offsets(Path('unused'),[102,200]),set())
  with patch('qcs.function_signatures.function_regions',return_value=([(4096,100,bytes.fromhex('c40200dc74c3'),1)],['x86_64'])):
   self.assertEqual(aes_instruction_offsets(Path('unused'),[100]),set())
 def test_real_aes_round_instruction_boundary_survives(self):
  with patch('qcs.function_signatures.function_regions',return_value=([(4096,100,bytes.fromhex('660f38dcc0660f38ddc0c3'),1)],['x86_64'])):
   self.assertEqual(aes_instruction_offsets(Path('unused'),[100,105]),{100})
 def test_real_generic_math_false_hit_is_retained_only_as_clue(self):
  p=WORKSPACE/'samples/controlflow-development-20261014/builds/static-ec-missing-multiply-x86_64-O2/ordinary.so';r=scan(p,'executable',Options(windriver=False))
  self.assertFalse(r['errors']);self.assertEqual(predictions(r,'implementation_contains'),set())
  self.assertTrue(any(c['identifier']=='AES_bytecode_AESNI_x64' and not c['decoded_instruction_offsets'] for c in r['clues']))
if __name__=='__main__':unittest.main()
