# Ruby taint-mode rule test fixtures.
# Verifies that Semgrep tracks data flow from params through assignments to sinks.

class TaintSecurityController < ApplicationController
  # --- taint-sql-injection ---

  def search_unsafe
    q = params[:q]
    # ruleid: ruby.security.taint-sql-injection
    User.where("name LIKE '%#{q}%'")
  end

  def search_unsafe_find_by_sql
    keyword = params.fetch(:keyword)
    # ruleid: ruby.security.taint-sql-injection
    User.find_by_sql("SELECT * FROM users WHERE name LIKE '%#{keyword}%'")
  end

  def search_unsafe_execute
    name = params["name"]
    sql = "SELECT * FROM users WHERE name = '#{name}'"
    # ruleid: ruby.security.taint-sql-injection
    ActiveRecord::Base.connection.execute(sql)
  end

  def search_safe
    q = params[:q]
    # ok: ruby.security.taint-sql-injection
    User.where("name LIKE ?", "%#{q}%")
  end

  # --- taint-command-injection ---

  def ping_unsafe
    host = params[:host]
    # ruleid: ruby.security.taint-command-injection
    system("ping -c 1 #{host}")
  end

  def run_unsafe_backticks
    script = params[:script]
    # ruleid: ruby.security.taint-command-injection
    `sh /tmp/#{script}`
  end

  def ping_safe
    host = params[:host].to_i
    # ok: ruby.security.taint-command-injection
    system("ping", "-c", "1", "host-#{host}")
  end

  # --- taint-path-traversal ---

  def export_unsafe
    filename = params[:file]
    path = Rails.root.join("exports", filename)
    # ruleid: ruby.security.taint-path-traversal
    send_file path
  end

  def read_unsafe
    name = params[:name]
    # ruleid: ruby.security.taint-path-traversal
    File.read("/data/#{name}.json")
  end

  def export_safe
    filename = File.basename(params[:file])
    # ok: ruby.security.taint-path-traversal
    send_file Rails.root.join("exports", filename)
  end

  # --- taint-ssrf ---

  def proxy_unsafe
    url = params[:url]
    # ruleid: ruby.security.taint-ssrf
    Net::HTTP.get(URI.parse(url))
  end

  def fetch_unsafe
    endpoint = params[:callback]
    # ruleid: ruby.security.taint-ssrf
    RestClient.get(endpoint)
  end

  def fetch_safe
    # ok: ruby.security.taint-ssrf
    Net::HTTP.get(URI.parse("https://api.example.com/health"))
  end

  # --- taint-xss ---

  def greet_unsafe
    name = params[:name]
    greeting = "Hello, " + name
    # ruleid: ruby.security.taint-xss
    render inline: "<h1>#{greeting}</h1>"
  end

  def raw_output_unsafe
    msg = params[:message]
    # ruleid: ruby.security.taint-xss
    raw(msg)
  end

  def greet_safe
    name = params[:name]
    # ok: ruby.security.taint-xss
    render plain: h(name)
  end

  # --- taint-deserialize ---

  def import_unsafe
    data = params[:payload]
    # ruleid: ruby.security.taint-deserialize
    YAML.load(data)
  end

  def load_unsafe_marshal
    blob = cookies[:session]
    raw = Base64.decode64(blob)
    # ruleid: ruby.security.taint-deserialize
    Marshal.load(raw)
  end

  def import_safe
    data = params[:config]
    # ok: ruby.security.taint-deserialize
    YAML.safe_load(data)
  end
end
