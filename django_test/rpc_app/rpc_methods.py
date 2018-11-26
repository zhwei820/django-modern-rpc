from modernrpc.core import rpc_method

@rpc_method
def add(a=200, b=33):
    return a + b

@rpc_method
def rpc_add(a=200, b=33):
    return a + b