"""Actual independent C++ record oracle build into fresh external output only."""
from pathlib import Path
import hashlib,json,subprocess
HERE=Path(__file__).resolve().parent
PROJECT=HERE.parents[2]
GRAMMAR=PROJECT/'docs/specifications/smir/portable/schema/runtime/source_carrier_records.json'
def build(output,*,compiler,sysroot=None):
    output=Path(output).resolve();compiler=Path(compiler)
    if not compiler.is_absolute()or not compiler.is_file():raise ValueError('absolute actual C++ compiler required')
    if output.is_relative_to(PROJECT):raise ValueError('external output required')
    output.mkdir(parents=True,exist_ok=False);D=output
    input_paths=[Path(__file__).resolve(),GRAMMAR,HERE/'cpp/codec-original.hpp',HERE/'cpp/probe.cpp',compiler]
    input_hashes={str(p):hashlib.sha256(p.read_bytes()).hexdigest()for p in input_paths}
    (D/'codec-original.hpp').write_bytes((HERE/'cpp/codec-original.hpp').read_bytes())
    size=GRAMMAR.stat().st_size
    if size>1<<20:raise ValueError('oracle schema bound')
    with GRAMMAR.open('rb')as stream:raw=stream.read(size+1)
    if len(raw)!=size or hashlib.sha256(raw).hexdigest()!='c64512a81e9716f1870e77c266d9de8aebf2b6ee7779f5dd44fb33a9aa8f9cb0':raise ValueError('oracle schema identity')
    g=json.loads(raw)
    def q(s):return json.dumps(s)
    def fields(fs):return '{'+','.join('{'+q(n)+','+q(k)+'}'for n,k in fs)+'}'
    rows=[]
    for name,r in sorted(g['records'].items()):
        variants='{'+','.join('{'+q(t)+','+fields(fs)+'}'for t,fs in r.get('variants',{}).items())+'}'
        rows.append('{'+q(name)+',{'+q(r.get('discriminator',''))+','+fields(r.get('fields',[]))+','+variants+'}}')
    (D/'schema.inc').write_text('const rax::smir::records::Schema smir_test_schema={'+','.join(rows)+'};\n')
    original=(D/'codec-original.hpp').read_text()
    source=original
    hooks=['static void v3_count(const std::string &path, std::uint64_t count) {']
    for path,cap in g['field_caps'].items():
        hooks.append('if(path=='+q(path)+' && !(count>='+str(cap['minimum'])+'ULL && count<='+str(cap['maximum'])+'ULL)) throw Error("V3-COUNT");')
    hooks+=['}','static void v3_scalar(const std::string &path,const Value &value) {','if(value.tag==Tag::Option || value.tag==Tag::Vector || value.tag==Tag::Record)return;']
    for path,rule in g['source_scalar_rules'].items():
        if 'anyOf'in rule:
            nonnull=[x for x in rule['anyOf']if x.get('type')!='null']
            if len(nonnull)==1:rule=nonnull[0]
        expr=[]
        if rule.get('type')=='integer':expr+=['value.number>='+str(rule['minimum'])+'ULL','value.number<='+str(rule['maximum'])+'ULL']
        vals=rule.get('enum')
        if vals:expr.append('('+' || '.join('value.data=='+q(v)for v in vals)+')')
        if 'const'in rule:
            v=rule['const']
            expr.append(('value.data=='+q(v))if type(v)is str else('value.number=='+str(int(v))+'ULL'))
        if expr:hooks.append('if(path=='+q(path)+' && !('+' && '.join(expr)+')) throw Error("V3-SCALAR");')
    hooks+=['}']
    needle='class Codec {'
    source=source.replace(needle,'\n'.join(hooks)+'\n'+needle,1)
    source=source.replace('std::size_t &cursor, std::size_t depth, std::size_t &nodes) const {','std::size_t &cursor, std::size_t depth, std::size_t &nodes, const std::string &path = "") const {',1)
    source=source.replace('result.tag = vector ? Tag::Vector : Tag::Option;','if(vector) v3_count(path,count);\n            result.tag = vector ? Tag::Vector : Tag::Option;',1)
    source=source.replace('read(type.substr(4), bytes, cursor, depth + 1, nodes)','read(type.substr(4), bytes, cursor, depth + 1, nodes, vector ? path + "[]" : path)',1)
    source=source.replace('const Fields *fields = &definition.fields;','const Fields *fields = &definition.fields;\n            std::string prefix=type;',1)
    source=source.replace('fields = &definition.variants.at(tag.data);','fields = &definition.variants.at(tag.data);\n                prefix += "." + tag.data;',1)
    source=source.replace('read(child, bytes, cursor, depth + 1, nodes)','read(child, bytes, cursor, depth + 1, nodes, prefix + "." + name)',1)
    source=source.replace('        return result;\n    }\n\n    void write','        v3_scalar(path,result);\n        return result;\n    }\n\n    void write',1)
    if source==original:raise SystemExit('no changes')
    (D/'codec.hpp').write_text(source)
    (D/'probe.cpp').write_bytes((HERE/'cpp/probe.cpp').read_bytes())
    argv=[str(compiler),'-std=c++20','-Wall','-Wextra','-Werror','-O2']
    if sysroot is not None:argv+=['-isysroot',str(sysroot)]
    argv+=[str(D/'probe.cpp'),'-o',str(D/'probe')]
    compiler_before=hashlib.sha256(compiler.read_bytes()).hexdigest()
    r=subprocess.run(argv,capture_output=True,text=True)
    drift=[str(p)for p in input_paths if hashlib.sha256(p.read_bytes()).hexdigest()!=input_hashes[str(p)]]
    compiler_after=hashlib.sha256(compiler.read_bytes()).hexdigest()
    (D/'build.json').write_text(json.dumps({'argv':argv,'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr,'input_hashes':input_hashes,'input_drift':drift,'compiler':{'path':str(compiler),'before_sha256':compiler_before,'after_sha256':compiler_after},'toolchain_limits':'System SDK headers/libraries and compiler subprocess file opens are not exhaustively attested.','scope':'Independent ordered payload decode/reencode only; no local reference validation, module digest, semantic admission or guest execution.','artifacts':{x.name:hashlib.sha256(x.read_bytes()).hexdigest()for x in D.iterdir()if x.is_file()and x.name not in('build.json','probe')}},indent=2)+'\n')
    if r.returncode or drift or compiler_before!=compiler_after:raise RuntimeError('SOURCE_CARRIER_ORACLE_BUILD_FAILED')
    return D/'probe'

def main():
    import argparse
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--compiler',type=Path,required=True);p.add_argument('--sysroot',type=Path)
    args=p.parse_args();print(build(args.output,compiler=args.compiler,sysroot=args.sysroot))
if __name__=='__main__':main()
