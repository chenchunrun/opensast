import ast

user_input = "print('hello')"

# Positive: eval with non-literal argument
# ruleid: python.security.eval-usage
eval(user_input)

# ruleid: python.security.eval-usage
eval(request.args.get("expr"))

# ruleid: python.security.eval-usage
result = eval(data["expression"])

# Negative: eval with literal string
# ok: python.security.eval-usage
eval("2+2")

# ok: python.security.eval-usage
eval("len([1, 2, 3])")

# ok: python.security.eval-usage
ast.literal_eval(user_input)
