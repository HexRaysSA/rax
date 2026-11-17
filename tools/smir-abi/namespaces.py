"""Closed ABI entity namespaces; IDs never select a table by coincidence."""
from dataclasses import dataclass

from layout import require
from nominal import unique

TABLES = {'nominal':'types', 'signature':'signatures', 'bridge':'bridges',
          'journal':'journals', 'recipe':'recipes', 'storage_binding':'storage_bindings'}


@dataclass(frozen=True)
class Entity:
    namespace: str
    module: str
    identifier: int
    record: dict

    def as_namespace(self, expected):
        require(self.namespace == expected, 'ABI_CC_ENTITY_NAMESPACE')
        return self.record


class Entities:
    """Resolve admitted declarations through explicit provider-private bindings.

    bindings[owner][slot] is {module:provider, <namespace>:{decl:private_id}}.
    This reference does not choose deployments, validate exports or grant lifetime
    authority. The caller supplies the transactionally admitted binding graph.
    """
    def __init__(self, module, contract, modules=None, bindings=None):
        self.module = module
        self.modules = {**(modules or {}), module:contract}
        self.bindings = bindings or {}
        self.tables = {owner:{namespace:unique(document[table],namespace.upper())
                             for namespace,table in TABLES.items()}
                       for owner,document in self.modules.items()}

    def resolve(self, namespace, reference, owner=None):
        require(namespace in TABLES, 'ABI_CC_ENTITY_NAMESPACE')
        owner = self.module if owner is None else owner
        identifier = reference['id']
        if reference['module']['kind'] == 'dependency':
            binding = self.bindings.get(owner,{}).get(reference['module']['slot'])
            require(binding is not None and identifier in binding.get(namespace,{}),
                    'ABI_CC_UNBOUND_ENTITY_DECLARATION')
            owner,identifier = binding['module'],binding[namespace][identifier]
        else:
            require(reference['module']['kind'] == 'self', 'ABI_CC_ENTITY_REFERENCE')
        require(owner in self.tables and identifier in self.tables[owner][namespace],
                'ABI_CC_ENTITY_REFERENCE')
        return Entity(namespace,owner,identifier,self.tables[owner][namespace][identifier])

    def lookup(self, namespace, reference):
        return self.resolve(namespace,reference).as_namespace(namespace)
