//! INT032 source roles over actual context-branded ABI/type facts.
//! No source AST, provider binding, runtime registry or executable grant is issued.
use super::imports::nominal_expectation;
use super::records::{flag, number, require, token};
use crate::abi::AbiFacts;
use crate::context::{DeclaredEntity, EntityKey, ModuleRef, Namespace, ObjectContext};
use crate::context::{entity_ref, field, list, optional, text};
use crate::execution::{TypeFacts, TypeHandle};
use crate::limits::Budget;
use crate::wire::RecordValue;
use crate::{Error, ErrorClass};

const ROLE: &str = "RT_HELPER_SOURCE_ROLE";
const LAYOUT: &str = "RT_HELPER_SOURCE_LAYOUT";
const EXECUTION: &str = "RT_HELPER_SOURCE_EXECUTION";

fn unavailable() -> Error {
    Error::new(
        ErrorClass::UnavailableEvidence,
        "RT_HELPER_SOURCE_EVIDENCE_UNAVAILABLE",
        "checked source allocation or transport",
    )
}

struct Roles<'a> {
    ctx: &'a ObjectContext,
    types: &'a TypeFacts,
    abi: &'a AbiFacts,
}

impl<'a> Roles<'a> {
    fn source(&self, key: EntityKey, budget: &mut Budget) -> Result<&RecordValue, Error> {
        budget.work(1)?;
        Ok(self.abi.nominal(key)?.record())
    }
    fn allocation(&self, key: EntityKey, budget: &mut Budget) -> Result<&RecordValue, Error> {
        budget.work(1)?;
        Ok(self
            .abi
            .nominal(key)?
            .layout()
            .ok_or_else(unavailable)?
            .record())
    }
    fn execution(&self, key: EntityKey, budget: &mut Budget) -> Result<TypeHandle, Error> {
        budget.work(1)?;
        self.abi
            .nominal(key)?
            .execution_type()
            .ok_or_else(unavailable)
    }
    fn has(&self, value: &RecordValue, name: &str, budget: &mut Budget) -> Result<bool, Error> {
        let flags = list(field(value, "flags")?)?;
        budget.work(flags.len() as u64 + 1)?;
        for entry in flags {
            if text(entry)? == name {
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn complete(&self, value: &RecordValue, budget: &mut Budget) -> Result<(), Error> {
        require(self.has(value, "complete", budget)?, ROLE)
    }
    fn extent(&self, value: &RecordValue, size: u64, align: u64) -> Result<(), Error> {
        require(
            number(value, "size")? == size
                && number(value, "data_size")? == size
                && number(value, "nonvirtual_size")? == size
                && number(value, "align")? == align
                && number(value, "nonvirtual_align")? == align,
            LAYOUT,
        )
    }
    fn atomic_flag(&self, key: EntityKey, budget: &mut Budget) -> Result<(), Error> {
        let source = self.source(key, budget)?;
        // A known wrong kind precedes any missing geometry evidence.
        require(token(source, "kind")? == "atomic_flag", ROLE)?;
        self.complete(source, budget)?;
        self.extent(self.allocation(key, budget)?, 1, 1)?;
        let execution = self.types.type_record(self.execution(key, budget)?)?;
        require(
            token(execution, "kind")? == "raw" && number(execution, "bits")? == 8,
            EXECUTION,
        )
    }
    fn builtin(&self, value: &RecordValue, kind: &str, entity: &str) -> Result<(), Error> {
        let identity = field(value, "identity")?;
        require(
            token(value, "kind")? == kind
                && token(identity, "language")? == "c23"
                && token(identity, "linkage")? == "builtin"
                && token(identity, "entity")? == entity
                && optional(field(identity, "library")?)?.is_none()
                && optional(field(identity, "unit")?)?.is_none(),
            ROLE,
        )?;
        let flags = list(field(value, "flags")?)?;
        require(
            flags.len() == 3
                && text(&flags[0])? == "complete"
                && text(&flags[1])? == "trivial_copy"
                && text(&flags[2])? == "trivial_destroy"
                && list(field(value, "qualifiers")?)?.is_empty()
                && list(field(value, "methods")?)?.is_empty()
                && list(field(value, "enumerators")?)?.is_empty(),
            ROLE,
        )
    }
    fn no_members(&self, layout: &RecordValue) -> Result<(), Error> {
        require(
            list(field(layout, "fields")?)?.is_empty()
                && list(field(layout, "bases")?)?.is_empty()
                && list(field(layout, "vptrs")?)?.is_empty(),
            LAYOUT,
        )
    }
    fn word(&self, key: EntityKey, bits: u64, budget: &mut Budget) -> Result<(), Error> {
        let value = self.source(key, budget)?;
        self.builtin(
            value,
            "scalar",
            if bits == 32 {
                "unsigned int"
            } else {
                "unsigned long"
            },
        )?;
        require(
            number(value, "bits")? == bits
                && !flag(value, "signed")?
                && list(field(value, "elements")?)?.is_empty()
                && optional(field(value, "extent")?)?.is_none()
                && optional(field(value, "record_input")?)?.is_none()
                && token(value, "representation")? == "value",
            ROLE,
        )?;
        self.extent(self.allocation(key, budget)?, bits / 8, bits / 8)?;
        let actual = self.types.type_record(self.execution(key, budget)?)?;
        require(
            token(actual, "kind")? == "int" && number(actual, "bits")? == bits,
            EXECUTION,
        )
    }
    fn state_execution(&self, handle: TypeHandle, budget: &mut Budget) -> Result<(), Error> {
        budget.work(2)?;
        let value = self.types.type_record(handle)?;
        require(
            token(value, "kind")? == "array" && number(value, "count")? == 32,
            EXECUTION,
        )?;
        let element = self
            .types
            .type_record(self.types.type_reference(field(value, "element")?)?)?;
        require(
            token(element, "kind")? == "raw" && number(element, "bits")? == 8,
            EXECUTION,
        )
    }
    fn state(&self, key: EntityKey, entity: &str, budget: &mut Budget) -> Result<(), Error> {
        let value = self.source(key, budget)?;
        self.builtin(value, "record", entity)?;
        require(
            number(value, "bits")? == 0
                && !flag(value, "signed")?
                && list(field(value, "elements")?)?.is_empty()
                && optional(field(value, "extent")?)?.is_none()
                && token(value, "representation")? == "storage",
            ROLE,
        )?;
        let input = optional(field(value, "record_input")?)?.ok_or_else(unavailable)?;
        require(
            number(input, "revision")? == 1
                && token(input, "kind")? == "struct"
                && optional(field(input, "explicit_align")?)?.is_none()
                && list(field(input, "bases")?)?.is_empty(),
            ROLE,
        )?;
        for name in [
            "pod03",
            "trivial",
            "standard_layout",
            "polymorphic",
            "dynamic",
            "empty",
        ] {
            require(!flag(input, name)?, ROLE)?;
        }
        let expected: &[(&str, u64, u64)] = if entity == "rax.va_state" {
            &[
                ("area", 64, 0),
                ("cursor", 64, 8),
                ("limit", 64, 16),
                ("cookie", 64, 24),
            ]
        } else {
            &[
                ("revision", 32, 0),
                ("reserved", 32, 4),
                ("process", 64, 8),
                ("checkpoint", 64, 16),
                ("generation", 64, 24),
            ]
        };
        let layout = self.allocation(key, budget)?;
        self.extent(layout, 32, 8)?;
        let inputs = list(field(input, "fields")?)?;
        let outputs = list(field(layout, "fields")?)?;
        require(
            inputs.len() == expected.len()
                && outputs.len() == expected.len()
                && list(field(layout, "bases")?)?.is_empty()
                && list(field(layout, "vptrs")?)?.is_empty(),
            ROLE,
        )?;
        budget.edges(expected.len())?;
        for (index, ((name, bits, offset), (input, output))) in
            expected.iter().zip(inputs.iter().zip(outputs)).enumerate()
        {
            budget.work(16)?;
            require(
                optional(field(input, "name")?)?.map(text).transpose()? == Some(*name)
                    && optional(field(input, "bit_width")?)?.is_none()
                    && optional(field(input, "explicit_align")?)?.is_none()
                    && !flag(input, "no_unique_address")?
                    && !flag(input, "anonymous")?
                    && token(input, "access")? == "public",
                ROLE,
            )?;
            require(
                number(output, "declaration_index")? == index as u64
                    && token(output, "name")? == *name
                    && field(output, "type")? == field(input, "type")?
                    && number(output, "offset_bits")? == offset * 8
                    && number(output, "width_bits")? == *bits
                    && list(field(output, "flags")?)?.is_empty(),
                ROLE,
            )?;
            self.word(
                nominal_expectation(self.ctx, field(input, "type")?)?,
                *bits,
                budget,
            )?;
        }
        self.state_execution(self.execution(key, budget)?, budget)
    }
    fn wrapper(&self, key: EntityKey, entity: &str, budget: &mut Budget) -> Result<(), Error> {
        let value = self.source(key, budget)?;
        self.builtin(value, "array", "array")?;
        let elements = list(field(value, "elements")?)?;
        require(
            number(value, "bits")? == 0
                && !flag(value, "signed")?
                && optional(field(value, "extent")?)?
                    .map(crate::context::unsigned)
                    .transpose()?
                    == Some(1)
                && elements.len() == 1
                && optional(field(value, "record_input")?)?.is_none()
                && token(value, "representation")? == "value",
            ROLE,
        )?;
        let layout = self.allocation(key, budget)?;
        self.extent(layout, 32, 8)?;
        self.no_members(layout)?;
        self.state(nominal_expectation(self.ctx, &elements[0])?, entity, budget)?;
        let execution = self.types.type_record(self.execution(key, budget)?)?;
        require(
            token(execution, "kind")? == "array" && number(execution, "count")? == 1,
            EXECUTION,
        )?;
        self.state_execution(
            self.types.type_reference(field(execution, "element")?)?,
            budget,
        )
    }
    fn object(&self, key: EntityKey, reference: bool, budget: &mut Budget) -> Result<(), Error> {
        let value = self.source(key, budget)?;
        let kind = token(value, "kind")?;
        require(
            !["void", "function", "handle", "snapshot"].contains(&kind)
                && (reference || kind != "reference"),
            ROLE,
        )?;
        self.complete(value, budget)?;
        self.allocation(key, budget)?;
        self.execution(key, budget)?;
        if kind == "reference" {
            self.extent(self.allocation(key, budget)?, 8, 8)?;
            let elements = list(field(value, "elements")?)?;
            require(
                elements.len() == 1
                    && (self.has(value, "lvalue_ref", budget)?
                        ^ self.has(value, "rvalue_ref", budget)?),
                ROLE,
            )?;
            self.source(nominal_expectation(self.ctx, &elements[0])?, budget)?;
            let execution = self.types.type_record(self.execution(key, budget)?)?;
            require(
                token(execution, "kind")? == "data_ptr"
                    && token(execution, "space")? == "guest_data",
                EXECUTION,
            )?;
        }
        Ok(())
    }
    fn va_arg(
        &self,
        key: EntityKey,
        record: &RecordValue,
        budget: &mut Budget,
    ) -> Result<(), Error> {
        self.object(key, false, budget)?;
        let source = self.source(key, budget)?;
        let kind = token(source, "kind")?;
        require(kind != "array", ROLE)?;
        if kind == "record" && token(field(source, "identity")?, "language")? == "cpp23" {
            require(
                self.has(source, "trivial_copy", budget)?
                    && self.has(source, "trivial_destroy", budget)?,
                ROLE,
            )?;
        }
        let parameters = list(field(record, "types")?)?;
        require(parameters.len() == 1, EXECUTION)?;
        require(
            self.types.type_equivalent(
                self.execution(key, budget)?,
                self.types.type_reference(&parameters[0])?,
                budget,
            )?,
            EXECUTION,
        )
    }
    fn eh(&self, key: EntityKey, budget: &mut Budget) -> Result<(), Error> {
        self.object(key, false, budget)?;
        let value = self.source(key, budget)?;
        require(token(value, "kind")? != "array", ROLE)?;
        for qualifier in list(field(value, "qualifiers")?)? {
            budget.work(1)?;
            require(!["const", "volatile"].contains(&text(qualifier)?), ROLE)?;
        }
        if token(value, "kind")? == "pointer" {
            let elements = list(field(value, "elements")?)?;
            require(elements.len() == 1, ROLE)?;
            let pointee = self.source(nominal_expectation(self.ctx, &elements[0])?, budget)?;
            if !["void", "function"].contains(&token(pointee, "kind")?) {
                self.complete(pointee, budget)?;
            }
        }
        Ok(())
    }
    fn tls(&self, key: EntityKey, record: &RecordValue, budget: &mut Budget) -> Result<(), Error> {
        self.object(key, true, budget)?;
        let target =
            optional(field(field(record, "options")?, "target")?)?.ok_or_else(unavailable)?;
        let reference = entity_ref(target)?;
        let nominal = match reference.module {
            ModuleRef::SelfModule => {
                let target = self
                    .ctx
                    .entity(self.ctx.local(Namespace::Tls, reference.id)?)?;
                optional(field(field(target, "storage")?, "nominal")?)?.ok_or_else(unavailable)?
            }
            ModuleRef::Dependency { .. } => match self
                .ctx
                .resolve_declaration(Namespace::Symbol, &reference)?
            {
                DeclaredEntity::Dependency { declaration, .. } => {
                    optional(field(declaration, "nominal")?)?.ok_or_else(unavailable)?
                }
                DeclaredEntity::Local(_) => return Err(unavailable()),
            },
        };
        let target = nominal_expectation(self.ctx, nominal)?;
        self.object(target, true, budget)?;
        require(
            self.abi.source_compatible(key, target, budget)?,
            "RT_HELPER_SOURCE_COMPATIBILITY",
        )
    }
}

pub(crate) fn verify(
    ctx: &ObjectContext,
    types: &TypeFacts,
    abi: &AbiFacts,
    key: EntityKey,
    record: &RecordValue,
    budget: &mut Budget,
) -> Result<(), Error> {
    types.assert_context(ctx)?;
    abi.assert_context(ctx)?;
    budget.work(8)?;
    let roles = Roles { ctx, types, abi };
    match token(record, "name")? {
        "atomic_flag_test" | "atomic_flag_test_and_set" | "atomic_flag_clear" => {
            roles.atomic_flag(key, budget)
        }
        "guard_acquire" | "guard_release" | "guard_abort" | "tls_guard_acquire"
        | "tls_guard_release" | "tls_guard_abort" => roles.object(key, true, budget),
        "va_start" | "va_copy" | "va_end" => roles.wrapper(key, "rax.va_state", budget),
        "setjmp_capture" | "longjmp_restore" => roles.wrapper(key, "rax.jmp_state", budget),
        "va_arg" => roles.va_arg(key, record, budget),
        "eh_allocate" => roles.eh(key, budget),
        "tls_address" => roles.tls(key, record, budget),
        _ => Err(Error::semantic(ROLE, "unknown nominal helper role")),
    }
}
