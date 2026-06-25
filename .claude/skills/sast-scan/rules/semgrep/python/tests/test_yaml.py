import yaml

data = "key: value"

# Positive: yaml.load without SafeLoader
# ruleid: python.security.yaml-unsafe-load
yaml.load(data)

# ruleid: python.security.yaml-unsafe-load
config = yaml.load(open("config.yml", "r"))

# Negative: yaml.safe_load
# ok: python.security.yaml-unsafe-load
yaml.safe_load(data)

# ok: python.security.yaml-unsafe-load
yaml.safe_load(open("config.yml", "r"))

# Negative: yaml.load with SafeLoader
# ok: python.security.yaml-unsafe-load
yaml.load(data, Loader=yaml.SafeLoader)

# ok: python.security.yaml-unsafe-load
yaml.load(data, Loader=yaml.FullLoader)

# ok: python.security.yaml-unsafe-load
yaml.load(data, Loader=yaml.BaseLoader)
