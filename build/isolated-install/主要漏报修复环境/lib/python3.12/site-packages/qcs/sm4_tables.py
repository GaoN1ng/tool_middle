"""Exact four-byte SM4 T-table round dependencies, without a key-schedule gate.

Each table is the complete standard tau+L map. All four indexed byte reads
must originate in the same word, with the correct input/output byte positions.
An unused table, arbitrary reads, or XORs of different input words cannot match.
"""
from .guomi.linear import bits, canonical


class TableRounds:
    def __init__(self):
        self.reads = {}
        self.completed = set()

    def remember(self, value, index, table):
        value = canonical(value)
        if table.get('kind') != 'block_table' or table.get('byte_position') is None:
            return
        if value[0] != 'lin' or len(value[1]) != 1:
            return
        atoms = bits(index)
        if atoms is None or not atoms[0]:
            return
        # The table index is exactly a byte, or the high byte of a word.
        # Scale/address arithmetic is handled by the lifter, never guessed.
        if any(atoms[8:]):
            return
        if not all(atoms[i] == frozenset((ident, (bit + i) % 32) for ident, bit in atoms[0])
                   for i in range(8)):
            return
        if len(self.reads) >= 16000:
            self.reads.clear()
            self.completed.clear()
        identity, rotation = next(iter(value[1]))
        if rotation:
            return
        position = table['byte_position']
        source = frozenset((ident, (bit - position) % 32) for ident, bit in atoms[0])
        self.reads[identity] = (source, position)

    def witness(self, value):
        value = canonical(value)
        if value[0] != 'lin':
            return None
        grouped = {}
        for identity, rotation in value[1]:
            if identity not in self.reads:
                continue
            source, position = self.reads[identity]
            # Rotated single-table implementations compensate for the output
            # position by rotating that map. Bind the same rotation to the
            # source byte, rather than counting four lookups indiscriminately.
            source = frozenset((ident, (bit - rotation) % 32) for ident, bit in source)
            grouped.setdefault(source, {}).setdefault((position + rotation) % 32, set()).add((identity, rotation))
        for source, positions in grouped.items():
            if set(positions) != {0, 8, 16, 24} or any(len(v) != 1 for v in positions.values()):
                continue
            output = frozenset().union(*positions.values())
            connected = any(previous <= source for previous in self.completed)
            self.completed.add(output)
            return {'byte_positions': [0, 8, 16, 24], 'input_word': tuple(sorted(map(repr, source))),
                    'feedback': connected,
                    'relation': 'four complete SM4 tau+L tables applied to four bytes of one word'}
        return None
