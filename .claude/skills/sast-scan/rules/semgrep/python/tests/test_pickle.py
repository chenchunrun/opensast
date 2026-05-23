import pickle
import json

data = b"\x80\x04..."

# Positive: pickle.loads
# ruleid: python.security.pickle-load
pickle.loads(data)

# Positive: pickle.load
# ruleid: python.security.pickle-load
pickle.load(open("data.pkl", "rb"))

# ruleid: python.security.pickle-load
obj = pickle.loads(request.data)

# Negative: json.loads (safe alternative)
# ok: python.security.pickle-load
json.loads(data)

# ok: python.security.pickle-load
json.load(open("data.json", "r"))
