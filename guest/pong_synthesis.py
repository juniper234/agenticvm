"""Bounded test-driven arithmetic repair; no model or arbitrary code execution.

Enumerate expressions from numbers' formal input/output examples. This helper
is an explicit deterministic fallback, not language-model-generated source.
"""
import itertools
import math

CONTRACTS={
 'advance':(('position','velocity','dt'),[(10,5,2),(10,-5,2),(7,0,.5),(0,1,.25),(-2,3,.5),(4,2,0)],(20,0,7,.25,-.5,4)),
 'bounce':(('velocity',),[(9,),(-7,),(0,),(2.5,)],(-9,7,0,-2.5)),
 'clamp':(('value','low','high'),[(-3,0,20),(25,0,20),(7,0,20),(-10,-5,5),(-1,-5,5),(10,2,8)],(0,20,7,-5,-1,8)),
}


def synthesize(name):
    variables,examples,expected=CONTRACTS[name]
    seeds=[]
    for index,variable in enumerate(variables):
        values=tuple(row[index] for row in examples)
        seeds.extend([(variable,values),('(-'+variable+')',tuple(-v for v in values))])
    count=0
    def matches(candidate):
        nonlocal count
        count+=1
        if count>10000:raise RuntimeError('Arithmetic synthesis budget exhausted')
        return all(math.isfinite(v) and abs(v-e)<1e-8 for v,e in zip(candidate[1],expected))
    for candidate in seeds:
        if matches(candidate):return {'expression':candidate[0],'candidates_tested':count,'origin':'deterministic_example_synthesis'}
    operators=('min','max') if name=='clamp' else ('+','-','*','/')
    def combine(a,b,op):
        try:
            if op=='min':return ('Math.min('+a[0]+','+b[0]+')',tuple(min(x,y) for x,y in zip(a[1],b[1])))
            if op=='max':return ('Math.max('+a[0]+','+b[0]+')',tuple(max(x,y) for x,y in zip(a[1],b[1])))
            function={'+':lambda x,y:x+y,'-':lambda x,y:x-y,'*':lambda x,y:x*y,'/':lambda x,y:x/y}[op]
            return ('('+a[0]+op+b[0]+')',tuple(function(x,y) for x,y in zip(a[1],b[1])))
        except (ZeroDivisionError,OverflowError):return None
    pairs=[]
    for a,b,op in itertools.product(seeds,seeds,operators):
        candidate=combine(a,b,op)
        if candidate is not None:
            if matches(candidate):return {'expression':candidate[0],'candidates_tested':count,'origin':'deterministic_example_synthesis'}
            pairs.append(candidate)
    for pair,seed,op in itertools.product(pairs,seeds,operators):
        for a,b in ((pair,seed),(seed,pair)):
            candidate=combine(a,b,op)
            if candidate is not None and matches(candidate):
                return {'expression':candidate[0],'candidates_tested':count,'origin':'deterministic_example_synthesis'}
    raise RuntimeError('No arithmetic expression satisfies the examples')
