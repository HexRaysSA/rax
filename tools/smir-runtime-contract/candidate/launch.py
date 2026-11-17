"""Exact R036 sidecar selection over actual admitted module/runtime facts."""
import hashlib

from .errors import option, require
from .wire import validate_shape


MACHINES={'elf':('linux',{'x86_64','aarch64'}),'macho':('macos',{'x86_64','aarch64'}),
          'pe':('windows',{'x86_64','aarch64'})}


def validate(document, module, *, grants, deployment, payload=None, carrier_bytes=None):
    validate_shape('runtime_launch',document)
    require(document['revision']==1 and document['launch'] in {'explicit','installed','embedded'},'RT_LAUNCH_REVISION')
    require(document['carrier'] in {'raw',*MACHINES} and document['bootstrap_arch'] in {'none','x86_64','aarch64'},
            'RT_LAUNCH_CARRIER')
    manifest=module['manifest']
    require(manifest['kind']=='image' and option(manifest['entry'])==document['entry'] and
            document['entry']['module']['kind']=='self','RT_LAUNCH_ENTRY')
    require(document['artifact']==manifest['identity'] and document['personality']==manifest['personality'] and
            document['foreign_isa']==manifest['foreign_isa'],'RT_LAUNCH_IDENTITY')
    caps=document['required_capabilities']
    require(caps==sorted(set(caps)) and set(caps)<=set(grants),'RT_LAUNCH_CAPABILITY')
    require(document['modules']==list(dict.fromkeys(document['modules'])),'RT_LAUNCH_MODULES')
    if document['launch']=='embedded':
        require(option(document['runtime']['implementation']) is not None and document['modules'] and
                document['modules']==deployment,'RT_LAUNCH_EMBEDDED')
    else:require(not document['modules'],'RT_LAUNCH_UNEXPECTED_MODULES')
    selection=document['runtime']
    require(selection['abi_major']==0 and selection['minimum_minor']==1 and selection['profile']==2,
            'RT_LAUNCH_PROFILE')
    locator=option(document['locator'])
    if document['carrier']=='raw':
        require(document['launch']=='explicit' and document['bootstrap_arch']=='none' and locator is None,
                'RT_LAUNCH_RAW')
    else:
        require(document['bootstrap_arch']!='none' and locator is not None,'RT_LAUNCH_BOOTSTRAP')
        require(type(payload) is bytes and type(carrier_bytes) is bytes,'RT_LAUNCH_CARRIER_BYTES')
        from . import locator as locator_codec
        actual=locator_codec.discover(carrier_bytes,document['carrier'])
        require(actual['payload']==payload and all(actual[k]==locator[k] for k in ['offset','length','sha256']) and
                locator['length']==len(payload) and locator['length']>0 and
                locator['sha256']==hashlib.sha256(payload).hexdigest() and
                locator['offset']+locator['length']<=len(carrier_bytes) and
                carrier_bytes[locator['offset']:locator['offset']+locator['length']]==payload,
                'RT_LAUNCH_LOCATOR')
    return document


def select(document,candidates,*,host_os,host_arch,baseline,helpers,services,grants):
    """First configured immutable candidate only; no path or native loader here."""
    require(candidates,'RT_LAUNCH_RUNTIME_NOT_FOUND')
    actual=candidates[0]
    requested=document['runtime']
    require(actual['os']==host_os and actual['arch']==host_arch,'RT_LAUNCH_RUNTIME_HOST')
    if document['launch'] in {'installed','embedded'}:
        require(document['carrier'] in MACHINES and MACHINES[document['carrier']][0]==host_os and
                document['bootstrap_arch']==host_arch,'RT_LAUNCH_BOOTSTRAP_HOST')
    require(actual['abi_major']==requested['abi_major'] and actual['abi_minor']>=requested['minimum_minor'] and
            actual['revision']>=requested['minimum_revision'],'RT_LAUNCH_RUNTIME_VERSION')
    identity=option(requested['implementation'])
    require(identity is None or actual['identity']==identity,'RT_LAUNCH_RUNTIME_IDENTITY')
    for name,value in [('baseline',baseline),('helpers',helpers),('services',services)]:
        require(requested[name]==actual[name]==value,'RT_LAUNCH_RUNTIME_'+name.upper())
    require(actual['profile']==requested['profile']==2,'RT_LAUNCH_PROFILE')
    require(document['personality'] in actual['personalities'] and document['foreign_isa'] in actual['foreign_isas'],
            'RT_LAUNCH_RUNTIME_ADAPTER')
    require(set(document['required_capabilities'])<=set(grants)&set(actual['capabilities']),
            'RT_LAUNCH_CAPABILITY')
    return actual
