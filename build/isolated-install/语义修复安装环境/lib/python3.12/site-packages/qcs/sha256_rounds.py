"""Exact Ch/Maj input bindings in SHA-256 T1+T2 round equations.

Expanded message words can be supplied by another function. Round evidence
still requires used standard K values and the SHA-256 variant initializer.
"""
from .guomi.linear import canonical


class RoundEquations:
    def __init__(self, arithmetic):
        self.arithmetic = arithmetic
        self.nodes = {}

    def remember(self, op, values, out):
        # Identity masks and casts must not redefine an existing leaf in
        # terms of itself (e.g. x & UINT32_MAX). Keep its original producer.
        if out in values:
            return
        if out[0] != 'lin' or len(out[1]) != 1:
            return
        identity, rotation = next(iter(out[1]))
        if rotation:
            return
        if len(self.nodes) >= 16000:
            self.nodes.clear()
        self.nodes[identity] = (op, tuple(values))

    def polynomial(self, value, depth=0):
        if depth > 8:
            return None
        value = canonical(value)
        if value[0] == 'constant':
            return frozenset() if value[1] == 0 else frozenset({frozenset()}) if value[1] & 0xffffffff == 0xffffffff else None
        if value[0] != 'lin' or len(value[1]) > 12:
            return None
        result = frozenset()
        for identity, rotation in value[1]:
            if rotation:
                return None
            if identity in self.nodes:
                op, arguments = self.nodes[identity]
                polynomials = [self.polynomial(v, depth + 1) for v in arguments]
                if any(v is None for v in polynomials):
                    return None
                a = polynomials[0]
                if op == 'not':
                    term = a ^ frozenset({frozenset()})
                else:
                    b = polynomials[1]
                    products = set()
                    for left in a:
                        for right in b:
                            item = left | right
                            if len(item) > 3:
                                return None
                            if item in products: products.remove(item)
                            else: products.add(item)
                    product = frozenset(products)
                    term = product if op == 'and' else a ^ b ^ product
            else:
                term = frozenset({frozenset({identity})})
            result ^= term
            if len(result) > 16:
                return None
        return result

    def boolean_role(self, value):
        p = self.polynomial(value)
        if p is None:
            return None
        variables = set().union(*p) if p else set()
        if len(variables) != 3:
            return None
        pairs = frozenset(frozenset({a, b}) for a in variables for b in variables if a != b)
        if p == pairs:
            return 'majority', frozenset(variables)
        singles = [next(iter(term)) for term in p if len(term) == 1]
        if len(singles) != 1 or len(p) != 3:
            return None
        g = singles[0]
        for e in variables - {g}:
            f = next(iter(variables - {g, e}))
            if p == frozenset({frozenset({g}), frozenset({e, f}), frozenset({e, g})}):
                return 'choice', (e, f, g)
        return None

    def additions(self, value, depth=0):
        if depth > 8:
            return [value]
        if value[0] == 'lin' and len(value[1]) == 1:
            identity, rotation = next(iter(value[1]))
            pair = self.arithmetic.sums.get(identity) if not rotation else None
            if pair:
                return self.additions(pair[0], depth + 1) + self.additions(pair[1], depth + 1)
        return [value]

    @staticmethod
    def sigma(value, rotations):
        value = canonical(value)
        if value[0] != 'lin' or len(value[1]) != 3:
            return None
        identities = {identity for identity, _ in value[1]}
        if any('wide' in identity[1] for identity in identities):
            return None
        return next(iter(identities)) if len(identities) == 1 and {r for _, r in value[1]} == set(rotations) else None

    def witness(self, value):
        # Most instruction outputs are not sums. Avoid expanding bit vectors.
        if value[0] != 'lin' or len(value[1]) != 1:
            return False
        terms = self.additions(value)
        if not 7 <= len(terms) <= 12:
            return False
        a_values = {x for term in terms if (x := self.sigma(term, (30, 19, 10))) is not None}
        e_values = {x for term in terms if (x := self.sigma(term, (26, 21, 7))) is not None}
        if not a_values or not e_values:
            return False
        boolean = [role for term in terms if (role := self.boolean_role(term)) is not None]
        majorities = [v for role, v in boolean if role == 'majority']
        choices = [v for role, v in boolean if role == 'choice']
        return any(a in majority and choice[0] in e_values and a != choice[0]
                   and not (majority & set(choice))
                   for a in a_values for majority in majorities for choice in choices)
