"""Arithmetic repair searches must generalize beyond their example corpus."""
import importlib.util
from pathlib import Path
import random
import unittest

spec=importlib.util.spec_from_file_location('pong_synthesis_test',Path(__file__).resolve().parents[1]/'guest/pong_synthesis.py')
synthesis=importlib.util.module_from_spec(spec)
spec.loader.exec_module(synthesis)


class SynthesisTests(unittest.TestCase):
    def test_repaired_expressions_match_unseen_numeric_cases(self):
        rng=random.Random(17)
        expected={'advance':lambda position,velocity,dt:position+velocity*dt,
                  'bounce':lambda velocity:-velocity,
                  'clamp':lambda value,low,high:max(low,min(high,value))}
        for name in ('advance','bounce','clamp'):
            repair=synthesis.synthesize(name)
            self.assertLess(repair['candidates_tested'],10000)
            self.assertEqual(repair['origin'],'deterministic_example_synthesis')
            expression=repair['expression'].replace('Math.min','min').replace('Math.max','max')
            for _ in range(100):
                values=({'position':rng.uniform(-50,50),'velocity':rng.uniform(-30,30),'dt':rng.uniform(0,3)} if name=='advance' else
                        {'velocity':rng.uniform(-30,30)} if name=='bounce' else
                        {'value':rng.uniform(-50,50),'low':-10,'high':15})
                actual=eval(expression,{'__builtins__':{},'min':min,'max':max},values)
                self.assertAlmostEqual(actual,expected[name](**values),places=8)

    def test_unknown_contract_cannot_select_an_unbounded_task(self):
        with self.assertRaises(KeyError):synthesis.synthesize('shell')


if __name__=='__main__':unittest.main()
