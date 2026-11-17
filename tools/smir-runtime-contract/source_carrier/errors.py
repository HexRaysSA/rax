"""Symbolic experimental source-carrier rejection codes."""
class CarrierError(ValueError):
    def __init__(self,code,detail=''):
        self.code=code;self.detail=detail;super().__init__(code+(': '+detail if detail else''))
def need(value,code,detail=''):
    if not value:raise CarrierError(code,detail)
