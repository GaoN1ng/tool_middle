"""Recognize actual sm-crypto API calls with a JavaScript AST and bindings.

No source is executed. Only explicit module imports/require, const aliases and
static property access are followed. Mutable/reassigned bindings and dynamic
properties stay unresolved. This deliberately replaces upstream regex guesses.
"""
from __future__ import annotations
import importlib.metadata
from ..model import evidence, error, sha256
from . import API_RULES, API_PATH

FUNCTIONS = {'function_declaration','function_expression','arrow_function','method_definition','generator_function','generator_function_declaration'}


class Scope:
    def __init__(self,parent=None):
        self.parent = parent
        self.bindings = {}
        self.invalid = set()

    def lookup(self,name,include_invalid=False):
        if name in self.bindings:
            return self.bindings[name] if include_invalid or name not in self.invalid else None
        return self.parent.lookup(name,include_invalid) if self.parent else None

    def declared(self,name):
        return name in self.bindings or bool(self.parent and self.parent.declared(name))


def scan_javascript(path,report):
    from tree_sitter import Language, Parser
    import tree_sitter_javascript
    raw = path.read_bytes()
    if len(raw)>4*1024*1024:
        error(report,'guomi_javascript','max_source_bytes','JavaScript AST scan is limited to 4 MiB per file','partial')
        report['scan_status']='partial'
        return
    try:
        raw.decode('utf-8')
    except UnicodeDecodeError:
        error(report,'guomi_javascript','source_encoding','JavaScript AST input must be valid UTF-8','partial')
        report['scan_status']='partial'
        return
    root = Parser(Language(tree_sitter_javascript.language())).parse(raw).root_node
    text = lambda n: raw[n.start_byte:n.end_byte].decode('utf-8',errors='replace') if n else ''

    def field(n,name):
        return n.child_by_field_name(name)

    def names(pattern):
        if pattern is None:return []
        if pattern.type in {'identifier','shorthand_property_identifier_pattern'}:return [text(pattern)]
        if pattern.type in {'pair_pattern','assignment_pattern'}:
            return names(field(pattern,'value') or field(pattern,'left'))
        return [name for child in pattern.named_children for name in names(child)]

    def literal(node):
        if not node or node.type!='string':return None
        value=text(node)
        # Escape decoding is deliberately unsupported: do not invent values.
        return value[1:-1] if len(value)>=2 and '\\' not in value else None

    def resolve(node,scope,include_invalid=False):
        if node is None:return None
        if node.type=='identifier':return scope.lookup(text(node),include_invalid)
        if node.type=='parenthesized_expression' and len(node.named_children)==1:
            return resolve(node.named_children[0],scope,include_invalid)
        if node.type in {'member_expression','subscript_expression'}:
            base=resolve(field(node,'object'),scope,include_invalid)
            prop=field(node,'property') if node.type=='member_expression' else field(node,'index')
            name=text(prop) if prop and prop.type=='property_identifier' else literal(prop)
            return base+(name,) if base is not None and name else None
        if node.type=='call_expression':
            fn=field(node,'function');args=field(node,'arguments')
            if fn and fn.type=='identifier' and text(fn)=='require' and not scope.declared('require') and args and len(args.named_children)==1:
                if literal(args.named_children[0])==API_RULES['js_library']:return ()
        return None

    def bind(pattern,value,scope):
        if pattern is None:return
        if pattern.type=='identifier':scope.bindings[text(pattern)]=value
        elif pattern.type=='object_pattern':
            for child in pattern.named_children:
                if child.type=='shorthand_property_identifier_pattern':
                    scope.bindings[text(child)]=value+(text(child),) if value is not None else None
                elif child.type=='pair_pattern':
                    key=field(child,'key');name=text(key) if key.type in {'property_identifier','identifier'} else literal(key)
                    bind(field(child,'value'),value+(name,) if value is not None and name else None,scope)

    def predeclare(node,scope):
        # Stop at nested lexical scopes and functions. Declare local names
        # before visits so later declarations cannot cause false outer matches.
        for child in node.named_children:
            if child.type in FUNCTIONS:
                name=field(child,'name')
                if name:scope.bindings[text(name)]=None
                continue
            if child.type=='statement_block':continue
            if child.type=='variable_declarator':
                for name in names(field(child,'name')):scope.bindings[name]=None
            elif child.type=='class_declaration':
                name=field(child,'name')
                if name:scope.bindings[text(name)]=None
            elif child.type=='import_statement':
                for c in child.named_children:
                    if c.type=='import_clause':
                        for n in names(c):scope.bindings[n]=None
            predeclare(child,scope)

    def hoist_vars(node,scope):
        for child in node.named_children:
            if child.type in FUNCTIONS:continue
            if child.type=='variable_declarator' and child.parent.type=='variable_declaration':
                for name in names(field(child,'name')):scope.bindings[name]=None
            hoist_vars(child,scope)

    def mutations(node):
        # Conservatively suppress any reassigned name/object across the source,
        # including writes inside callbacks. This trades recall for clear basis.
        result=set()
        stack=[node]
        while stack:
            n=stack.pop()
            if n.type in {'assignment_expression','augmented_assignment_expression','update_expression'}:
                left=field(n,'left') or field(n,'argument')
                while left and left.type in {'member_expression','subscript_expression'}:left=field(left,'object')
                if left and left.type=='identifier':result.add(text(left))
            stack.extend(n.named_children)
        return result

    invalid=mutations(root)
    calls=[]
    mutated_paths=[]

    def visit(node,scope):
        if node.type in {'program','statement_block'}:
            child_scope=Scope(scope) if node.type=='statement_block' else scope
            predeclare(node,child_scope)
            child_scope.invalid=invalid
            for child in node.named_children:visit(child,child_scope)
            return
        if node.type in FUNCTIONS:
            local=Scope(scope);local.invalid=invalid
            for name in names(field(node,'parameters') or field(node,'parameter')):local.bindings[name]=None
            name=field(node,'name')
            if name:local.bindings[text(name)]=None
            body=field(node,'body')
            if body:hoist_vars(body,local);visit(body,local)
            return
        if node.type=='import_statement':
            if literal(field(node,'source'))!=API_RULES['js_library']:return
            for clause in node.named_children:
                if clause.type!='import_clause':continue
                for c in clause.named_children:
                    if c.type=='identifier':scope.bindings[text(c)]=()
                    elif c.type=='namespace_import':scope.bindings[text(c.named_children[0])]=()
                    elif c.type=='named_imports':
                        for spec in c.named_children:
                            name=field(spec,'name');alias=field(spec,'alias') or name
                            scope.bindings[text(alias)]=(text(name),)
            return
        if node.type=='variable_declarator':
            value=field(node,'value')
            if value:visit(value,scope)
            if node.parent.type=='lexical_declaration' and node.parent.children[0].type=='const':
                bind(field(node,'name'),resolve(value,scope),scope)
            return
        if node.type=='catch_clause':
            local=Scope(scope);local.invalid=invalid
            for name in names(field(node,'parameter')):local.bindings[name]=None
            body=field(node,'body')
            if body:visit(body,local)
            return
        if node.type=='with_statement':
            # Its object can dynamically shadow every identifier in the body.
            return
        if node.type in {'assignment_expression','augmented_assignment_expression','update_expression'} or (
                node.type=='unary_expression' and text(field(node,'operator'))=='delete'):
            left=field(node,'left') or field(node,'argument')
            if left and left.type in {'member_expression','subscript_expression'}:
                target=resolve(left,scope,True)
                if target is None:target=resolve(field(left,'object'),scope,True)
                if target is not None:mutated_paths.append(target)
        if node.type=='call_expression':
            fn=field(node,'function');resolved=resolve(fn,scope)
            if resolved:
                export=resolved[0];operation='.'.join(resolved[1:])
                if operation in API_RULES['js_operations'].get(export,[]):
                    calls.append((node,fn,export,operation,resolved))
        # Comments, strings, regexes and template text contain no call ASTs.
        for child in node.named_children:visit(child,scope)

    scope=Scope();scope.invalid=invalid
    hoist_vars(root,scope)
    visit(root,scope)
    if root.has_error:
        error(report,'guomi_javascript','parse_error','JavaScript syntax errors; recovered calls are retained with partial scan status','partial')
        report['scan_status']='partial'
    for node,fn,export,operation,resolved in calls:
        if any(resolved[:len(target)]==target for target in mutated_paths):continue
        report['findings'].append(evidence(export.upper(),'guomi_javascript','source_api',text(fn),
            line=node.start_point.row+1, offset=node.start_byte, source_role='call',
            confidence='high', library='sm-crypto', resolved_api=export+('.'+operation if operation else ''),
            snippet=text(node)[:240], confidence_reason='JavaScript call AST resolves through explicit sm-crypto import/require and immutable bindings; runtime use unknown'))
    report['artifact'].update(format='JavaScript text',source_encoding='utf-8')
    if not root.has_error:report['engine_status']['guomi_javascript']={'status':'completed'}
    report['versions']['guomi_api_mapping_sha256']=sha256(API_PATH)
    report['versions']['tree_sitter']=importlib.metadata.version('tree-sitter')
    report['versions']['tree_sitter_javascript']=importlib.metadata.version('tree-sitter-javascript')
    report['coverage_notes'].append('Guomi JavaScript recognizes explicit sm-crypto calls and const aliases. Mutable bindings, dynamic imports/properties, reexports, minifier transformations and unrecorded libraries remain unresolved; source implementations are not inferred from API calls.')
