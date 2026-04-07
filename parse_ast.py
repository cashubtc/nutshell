import ast
code = """
assert (
    promises[0].C_
    == "031422eeffb25319e519c68de000effb294cb362ef713a7cf4832cea7b0452ba6e"
    ), f"Promise C_ mismatch: expected ...ba6e, got {promises[0].C_}"
"""
node = ast.parse(code)
for n in ast.walk(node):
    if isinstance(n, ast.Assert):
        print("Test:", type(n.test))
        print("Msg:", type(n.msg))
