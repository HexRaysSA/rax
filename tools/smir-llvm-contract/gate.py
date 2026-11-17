"""Validate draft compilation requests. This is not an LLVM IR verifier."""
from policy import ADDRESS_SPACES, DATALAYOUT, PIN, TRIPLE
from reference import ContractError

FIELDS = {'revision', 'llvm_revision', 'triple', 'datalayout', 'origin',
          'personality', 'carrier', 'address_spaces', 'inline_asm',
          'operand_bundles', 'module_flags'}


def validate_request(request, for_emission=False):
    if type(request) is not dict or request.keys() != FIELDS:
        raise ContractError('E-REQUEST-SCHEMA')
    if request['revision'] != 'llvm-request-draft-v1':
        raise ContractError('E-REQUEST-REVISION')
    if request['llvm_revision'] != PIN:
        raise ContractError('E-LLVM-REVISION')
    if request['triple'] != TRIPLE:
        raise ContractError('E-TARGET-TRIPLE')
    if request['datalayout'] != DATALAYOUT:
        raise ContractError('E-DATALAYOUT')
    if request['origin'] not in ('smir-frontend', 'handwritten-portable-ir'):
        raise ContractError('E-RETARGETED-HOST-IR')
    if request['personality'] not in ('linux', 'darwin', 'windows'):
        raise ContractError('E-PERSONALITY')
    if request['carrier'] not in ('elf', 'macho', 'pe'):
        raise ContractError('E-CARRIER')
    if (type(request['address_spaces']) is not list or
            request['address_spaces'] != list(ADDRESS_SPACES)):
        raise ContractError('E-ADDRESS-SPACE')
    if any(type(space) is not int for space in request['address_spaces']):
        raise ContractError('E-ADDRESS-SPACE')
    if type(request['inline_asm']) is not bool:
        raise ContractError('E-REQUEST-SCHEMA')
    if request['inline_asm']:
        raise ContractError('E-INLINE-ASSEMBLY')
    if type(request['operand_bundles']) is not list:
        raise ContractError('E-REQUEST-SCHEMA')
    if request['operand_bundles']:
        raise ContractError('E-OPERAND-BUNDLE')
    if type(request['module_flags']) is not dict:
        raise ContractError('E-REQUEST-SCHEMA')
    if request['module_flags']:
        raise ContractError('E-MODULE-FLAG')
    # A request that passes every check above is acceptable for emission. The
    # request carries no field that could widen what is accepted.
    return 'emission-request' if for_emission else 'draft-request-only'
