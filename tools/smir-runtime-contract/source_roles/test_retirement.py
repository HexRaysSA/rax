"""Actual private owner/address retirement; no synthetic controller identity."""
import unittest
if __package__:
    from .test_code_addresses import R,actual,policy
else:
    from test_code_addresses import R,actual,policy


class ActualRetirementTests(unittest.TestCase):
    def test_actual_idle_owner_reclaims_address_becomes_stale_metadata(self):
        context,source,budget=actual();registry=R.CodeRegistry(budget=budget,policy=policy())
        owner=registry.register_source(source,budget=budget)
        deployment=registry.prepare_deployment((owner,),budget=budget)
        target=registry.resolve(deployment,owner,'function',{'module':{'kind':'self'},'id':0},budget=budget)
        address=registry.address(target,budget=budget)
        transaction=registry.retire((owner,),budget=budget)
        self.assertEqual(registry.retire_poll(transaction,budget=budget).phase,'reclaimed')
        self.assertEqual(address.bits,2)
        with self.assertRaises(R.CodeRegistryError) as caught:registry.address(target,budget=budget)
        self.assertEqual(caught.exception.code,'code_address_stale')
        registry.drop_lane(address,budget=budget)

    def test_retirement_does_not_accept_model_owner_or_reopen(self):
        context,source,budget=actual();registry=R.CodeRegistry(budget=budget,policy=policy())
        with self.assertRaises(R.CodeRegistryError):registry.retire(({'owner':0},),budget=budget)
        owner=registry.register_source(source,budget=budget)
        registry.retire((owner,),budget=budget)
        with self.assertRaises(R.CodeRegistryError):registry.retire((owner,),budget=budget)


if __name__=='__main__':unittest.main()
