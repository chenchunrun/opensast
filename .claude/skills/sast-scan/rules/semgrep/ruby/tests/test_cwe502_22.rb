# CWE-502: Deserialization / CWE-22: Path Traversal
def test_deserialization(data)
  # ruleid: ruby.security.deserialization-yaml
  YAML.load(data)

  # ok: ruby.security.deserialization-yaml
  YAML.safe_load(data)
end

def test_path_traversal(params)
  # ruleid: ruby.security.path-traversal
  File.open(params[:file])
  # ruleid: ruby.security.path-traversal
  send_file(params[:download])
  # ruleid: ruby.security.path-traversal
  IO.read(params[:path])

  # ok: ruby.security.path-traversal
  File.open("config.yml")
  # ok: ruby.security.path-traversal
  send_file("/public/robots.txt")
end
