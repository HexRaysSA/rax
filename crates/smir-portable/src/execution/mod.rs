//! Static portable execution verification. Facts never authorize guest execution.

mod calls;
mod cfg;
mod exceptions;
mod identity;
mod layout;
mod memory;
mod model;
mod operations;
mod program;
mod pure;
mod records;
pub(crate) mod types;

pub(crate) use program::{
    ConstantProgramFact, FunctionFact, ProgramFacts, ProgramRequirement, verify_program,
};
#[cfg(test)]
pub(crate) use program::{check_function_core, check_function_source_and_eh};

use std::collections::BTreeMap;

use crate::context::{ContextId, EntityKey, Namespace, ObjectContext, field};
use crate::error::Error;
use crate::limits::Budget;
use crate::wire::RecordValue;

pub(crate) use model::{FloatFormat, OpaqueSet, TypeKind};
use records::{
    flag, identifier, local_reference, number, option, ordered, require, sequence, token,
};
use types::TypeGraph;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct TypeHandle {
    context: ContextId,
    id: u32,
}

impl TypeHandle {
    pub(crate) fn id(self) -> u32 {
        self.id
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct LayoutHandle {
    context: ContextId,
    id: u32,
}

impl LayoutHandle {
    pub(crate) fn id(self) -> u32 {
        self.id
    }
}

pub(crate) struct MemoryFieldFact {
    pub(crate) value_index: u32,
    pub(crate) bit_offset: u64,
    pub(crate) bit_width: u64,
    pub(crate) layout: LayoutHandle,
}

pub(crate) struct MemoryLayoutFact {
    pub(crate) id: u32,
    pub(crate) execution_type: TypeHandle,
    pub(crate) size_bytes: u64,
    pub(crate) alignment_bytes: u32,
    pub(crate) access_bytes: u64,
    pub(crate) fields: Vec<MemoryFieldFact>,
    pub(crate) element: Option<LayoutHandle>,
    /// Arrays use 8*child.size_bytes; vectors use child logical bit width.
    pub(crate) stride_bits: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EscapeKind {
    Propagate,
    Terminate,
    Nothrow,
}

pub(crate) struct LocalDeclFact {
    pub(crate) id: u32,
    pub(crate) ty: TypeHandle,
}

pub(crate) struct FunctionDeclFact {
    pub(crate) id: u32,
    pub(crate) signature: TypeHandle,
    pub(crate) abi_signature: Option<u32>,
    pub(crate) params: Vec<LocalDeclFact>,
    pub(crate) entry: u32,
    pub(crate) escape: EscapeKind,
    pub(crate) no_return: bool,
}

/// Complete type/layout graph and function headers, with no accepted bodies.
pub(crate) struct TypeFacts {
    identity: [u8; 32],
    context: ContextId,
    graph: TypeGraph,
    layouts: BTreeMap<u32, MemoryLayoutFact>,
    functions: BTreeMap<u32, FunctionDeclFact>,
}

pub(crate) fn verify_types(ctx: &ObjectContext, budget: &mut Budget) -> Result<TypeFacts, Error> {
    let graph = TypeGraph::build(ctx.root(1)?, ctx.root(2)?, budget)?;
    let raw_layouts = layout::build(ctx.root(1)?, &graph, budget)?;
    let context = ctx.context_id();
    let mut layouts = BTreeMap::new();
    for (id, raw) in raw_layouts {
        budget.work(1)?;
        budget.reserve_bytes(std::mem::size_of::<MemoryLayoutFact>() + 96)?;
        budget.reserve_bytes(
            raw.fields
                .len()
                .checked_mul(std::mem::size_of::<MemoryFieldFact>())
                .ok_or_else(|| Error::resource("reference_resource", "layout fact fields"))?,
        )?;
        let fields = raw
            .fields
            .into_iter()
            .map(|field| MemoryFieldFact {
                value_index: field.value_index,
                bit_offset: field.bit_offset,
                bit_width: field.bit_width,
                layout: LayoutHandle {
                    context,
                    id: field.layout,
                },
            })
            .collect();
        layouts.insert(
            id,
            MemoryLayoutFact {
                id,
                execution_type: TypeHandle {
                    context,
                    id: raw.execution_type,
                },
                size_bytes: raw.size_bytes,
                alignment_bytes: raw.alignment_bytes,
                access_bytes: raw.access_bytes,
                fields,
                element: raw.element.map(|id| LayoutHandle { context, id }),
                stride_bits: raw.stride_bits,
            },
        );
    }
    let functions_root = ctx.root(3)?;
    require(number(functions_root, "payload_revision")? == 2, "revision")?;
    let mut functions = BTreeMap::new();
    for (id, record) in ordered(sequence(functions_root, "functions")?, "id", budget)? {
        budget.work(1)?;
        require(id < u32::MAX, "function_id")?;
        let signature_id = graph.resolve(field(record, "signature")?)?;
        let TypeKind::Function {
            params: expected, ..
        } = &graph.node(signature_id)?.kind
        else {
            return Err(Error::semantic("function_signature", id.to_string()));
        };
        let params = sequence(record, "params")?;
        require(params.len() == expected.len(), "parameter_signature")?;
        budget.reserve_bytes(
            params
                .len()
                .checked_mul(std::mem::size_of::<LocalDeclFact>())
                .ok_or_else(|| Error::resource("reference_resource", "function params"))?,
        )?;
        let mut actual = Vec::with_capacity(params.len());
        for (param, expected) in params.iter().zip(expected) {
            budget.work(1)?;
            let ty = graph.resolve(field(param, "type")?)?;
            require(
                graph.equivalent(ty, *expected, budget)?,
                "parameter_signature",
            )?;
            actual.push(LocalDeclFact {
                id: identifier(param, "id")?,
                ty: TypeHandle { context, id: ty },
            });
        }
        let abi_signature = option(record, "abi_signature")?
            .map(local_reference)
            .transpose()?;
        if let Some(id) = abi_signature {
            ctx.local(Namespace::CallSignature, id)?;
        }
        let escape = match token(record, "escape")? {
            "propagate" => EscapeKind::Propagate,
            "terminate" => EscapeKind::Terminate,
            "nothrow" => EscapeKind::Nothrow,
            _ => return Err(Error::semantic("function_escape", id.to_string())),
        };
        budget.reserve_bytes(std::mem::size_of::<FunctionDeclFact>() + 96)?;
        functions.insert(
            id,
            FunctionDeclFact {
                id,
                signature: TypeHandle {
                    context,
                    id: signature_id,
                },
                abi_signature,
                params: actual,
                entry: identifier(record, "entry")?,
                escape,
                no_return: flag(record, "no_return")?,
            },
        );
    }
    Ok(TypeFacts {
        identity: ctx.identity(),
        context,
        graph,
        layouts,
        functions,
    })
}

impl TypeFacts {
    pub(crate) fn identity(&self) -> [u8; 32] {
        self.identity
    }
    pub(crate) fn context_id(&self) -> ContextId {
        self.context
    }

    pub(crate) fn assert_context(&self, ctx: &ObjectContext) -> Result<(), Error> {
        require(
            self.context == ctx.context_id() && self.identity == ctx.identity(),
            "execution_context",
        )
    }

    pub(crate) fn type_handle(&self, id: u32) -> Result<TypeHandle, Error> {
        self.graph.node(id)?;
        Ok(TypeHandle {
            context: self.context,
            id,
        })
    }

    pub(crate) fn type_from_entity(&self, key: EntityKey) -> Result<TypeHandle, Error> {
        require(
            key.context_id() == self.context && key.namespace() == Namespace::ExecutionType,
            "execution_context",
        )?;
        self.type_handle(key.id())
    }

    pub(crate) fn type_reference(&self, reference: &RecordValue) -> Result<TypeHandle, Error> {
        self.type_handle(self.graph.resolve(reference)?)
    }

    pub(crate) fn type_record(&self, ty: TypeHandle) -> Result<&RecordValue, Error> {
        require(ty.context == self.context, "execution_context")?;
        Ok(&self.graph.node(ty.id)?.raw)
    }

    pub(crate) fn kind(&self, ty: TypeHandle) -> Result<&TypeKind, Error> {
        require(ty.context == self.context, "execution_context")?;
        Ok(&self.graph.node(ty.id)?.kind)
    }

    pub(crate) fn layout_handle(&self, id: u32) -> Result<LayoutHandle, Error> {
        require(self.layouts.contains_key(&id), "layout_reference")?;
        Ok(LayoutHandle {
            context: self.context,
            id,
        })
    }

    pub(crate) fn layout_from_entity(&self, key: EntityKey) -> Result<LayoutHandle, Error> {
        require(
            key.context_id() == self.context && key.namespace() == Namespace::MemoryLayout,
            "execution_context",
        )?;
        self.layout_handle(key.id())
    }

    pub(crate) fn layout(&self, layout: LayoutHandle) -> Result<&MemoryLayoutFact, Error> {
        require(layout.context == self.context, "execution_context")?;
        self.layouts
            .get(&layout.id)
            .ok_or_else(|| Error::semantic("layout_reference", layout.id.to_string()))
    }

    pub(crate) fn function_decl(&self, id: u32) -> Result<&FunctionDeclFact, Error> {
        self.functions
            .get(&id)
            .ok_or_else(|| Error::semantic("function_reference", id.to_string()))
    }

    pub(crate) fn type_equivalent(
        &self,
        left: TypeHandle,
        right: TypeHandle,
        budget: &mut Budget,
    ) -> Result<bool, Error> {
        require(
            left.context == self.context && right.context == self.context,
            "execution_context",
        )?;
        self.graph.equivalent(left.id, right.id, budget)
    }

    pub(crate) fn type_identity(
        &self,
        ty: TypeHandle,
        budget: &mut Budget,
    ) -> Result<[u8; 32], Error> {
        require(ty.context == self.context, "execution_context")?;
        identity::type_digest(&self.graph, ty.id, budget)
    }

    pub(crate) fn value_bits(&self, ty: TypeHandle) -> Result<u64, Error> {
        require(ty.context == self.context, "execution_context")?;
        Ok(self.graph.node(ty.id)?.width)
    }

    pub(crate) fn present_opaque(&self, ty: TypeHandle) -> Result<OpaqueSet, Error> {
        require(ty.context == self.context, "execution_context")?;
        Ok(self.graph.node(ty.id)?.opaque)
    }

    pub(crate) fn present_fenv(&self, ty: TypeHandle) -> Result<bool, Error> {
        require(ty.context == self.context, "execution_context")?;
        Ok(self.graph.node(ty.id)?.fenv)
    }

    pub(crate) fn value_nodes(&self, ty: TypeHandle) -> Result<u64, Error> {
        require(ty.context == self.context, "execution_context")?;
        Ok(self.graph.node(ty.id)?.value_nodes)
    }
}
