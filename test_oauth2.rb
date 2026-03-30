#!/usr/bin/env ruby
# frozen_string_literal: true

#
# LavinMQ OAuth2 Integration Tests (AMQP + MQTT)
#
# Real end-to-end tests against a running LavinMQ and a real OIDC provider.
# Tokens are fetched via the OAuth2 client_credentials grant.
#
# Requirements:
#   gem install bunny mqtt
#
# Usage:
#   ruby test_oauth2.rb \
#     --issuer https://my-oidc-provider.example.com \
#     --client-id my-client \
#     --client-secret my-secret \
#     --amqp amqp://127.0.0.1:5672 \
#     --mqtt 127.0.0.1:1883 \
#     --http http://127.0.0.1:15672 \
#     --audience lavinmq \
#     --scope-prefix lavinmq.
#

require "bunny"
require "mqtt"
require "net/http"
require "json"
require "uri"
require "base64"
require "optparse"
require "timeout"

# ── Token fetching ────────────────────────────────────────────────────────────

def discover_token_endpoint(issuer)
  issuer = "https://#{issuer}" unless issuer.match?(%r{\Ahttps?://})
  url = URI("#{issuer.chomp('/')}/.well-known/openid-configuration")
  resp = Net::HTTP.get_response(url)
  raise "OIDC discovery failed: HTTP #{resp.code}" unless resp.is_a?(Net::HTTPSuccess)

  endpoint = JSON.parse(resp.body)["token_endpoint"]
  puts "  discovered token_endpoint: #{endpoint}"
  endpoint
end

def fetch_token(token_endpoint, client_id, client_secret, scope: nil, audience: nil)
  uri = URI(token_endpoint)
  params = {
    "grant_type"    => "client_credentials",
    "client_id"     => client_id,
    "client_secret" => client_secret,
  }
  # params["scope"] = scope if scope
  params["audience"] = audience if audience

  resp = Net::HTTP.post_form(uri, params)
  raise "Token request failed: HTTP #{resp.code} #{resp.body}" unless resp.is_a?(Net::HTTPSuccess)

  JSON.parse(resp.body)["access_token"]
end

# ── Test framework ────────────────────────────────────────────────────────────

$pass_count = 0
$fail_count = 0
$skip_count = 0

def pass!(name)
  $pass_count += 1
  puts "  PASS  #{name}"
end

def fail!(name, msg = "")
  $fail_count += 1
  puts "  FAIL  #{name}  -- #{msg}"
end

def skip!(name, msg = "")
  $skip_count += 1
  puts "  SKIP  #{name}  -- #{msg}"
end

def check(name, ok, msg = "")
  ok ? pass!(name) : fail!(name, msg)
end

# ── AMQP helpers ──────────────────────────────────────────────────────────────

def amqp_connect(url, token, vhost: "/")
  uri = URI(url)
  conn = Bunny.new(
    host: uri.host || "127.0.0.1",
    port: uri.port || 5672,
    vhost: vhost,
    username: "",
    password: token,
    connection_timeout: 5,
    read_timeout: 5,
  )
  conn.start
  conn
end

# ── MQTT helpers ──────────────────────────────────────────────────────────────

def mqtt_connect_client(host_port, token, client_id: nil)
  hp = host_port.sub(%r{\Amqtts?://}, "")
  host, _, port = hp.rpartition(":")
  host = "127.0.0.1" if host.empty?
  port = port.empty? ? 1883 : port.to_i
  client_id ||= "test-#{(Time.now.to_f * 1000).to_i}"
  MQTT::Client.connect(
    host: host,
    port: port.to_i,
    username: "jwt",
    password: token,
    client_id: client_id,
    keep_alive: 60,
  )
end

# ── Scope helpers ─────────────────────────────────────────────────────────────

def scoped(prefix, scopes)
  return scopes if prefix.nil? || prefix.empty?

  scopes.split.map { |s| "#{prefix}#{s}" }.join(" ")
end

def get_token(opts, token_endpoint, scope)
  token = fetch_token(token_endpoint, opts[:client_id], opts[:client_secret],
                      scope: scoped(opts[:scope_prefix], scope),
                      audience: opts[:audience])
  parts = token.split(".")
  if parts.size == 3
    payload = JSON.parse(Base64.urlsafe_decode64(parts[1] + "=" * (-parts[1].size % 4)))
    puts "  token scopes: #{payload["scope"]}" if payload["scope"]
  end
  token
end

# ── Tamper helper ─────────────────────────────────────────────────────────────

def tamper_token_expiry(token)
  parts = token.split(".")
  return nil unless parts.size == 3

  payload_json = Base64.urlsafe_decode64(parts[1] + "=" * (-parts[1].size % 4))
  payload = JSON.parse(payload_json)
  payload["exp"] = Time.now.to_i - 600
  new_payload = Base64.urlsafe_encode64(JSON.generate(payload)).tr("=", "")
  "#{parts[0]}.#{new_payload}.#{parts[2]}"
end

# ── AMQP tests ────────────────────────────────────────────────────────────────

def test_amqp_publish_consume(opts, token_endpoint)
  puts "\n== AMQP: publish & consume =="
  token = get_token(opts, token_endpoint, "read:%2F/* write:%2F/* configure:%2F/*")
  conn = amqp_connect(opts[:amqp], token)
  ch = conn.create_channel
  q = ch.queue("", exclusive: true)
  ch.default_exchange.publish("hello-oauth", routing_key: q.name)
  sleep 0.1
  _delivery_info, _properties, body = q.pop
  check("amqp publish+consume", body == "hello-oauth", "body=#{body.inspect}")
  conn.close
rescue => e
  fail!("amqp publish+consume", e.message)
end

def test_amqp_read_only(opts, token_endpoint)
  puts "\n== AMQP: read-only scope =="
  token = get_token(opts, token_endpoint, "read:%2F/*")
  conn = amqp_connect(opts[:amqp], token)
  ch = conn.create_channel
  begin
    ch.queue("oauth-test-readonly")
    fail!("read-only: declare rejected", "declare succeeded")
  rescue Bunny::AccessRefused
    pass!("read-only: declare rejected")
  end
  conn.close
rescue Bunny::PossibleAuthenticationFailureError
  pass!("read-only: declare rejected (connection level)")
rescue => e
  fail!("read-only: declare rejected", e.message)
end

def test_amqp_write_only(opts, token_endpoint)
  puts "\n== AMQP: write-only scope =="
  token = get_token(opts, token_endpoint, "write:%2F/* configure:%2F/*")
  conn = amqp_connect(opts[:amqp], token)
  ch = conn.create_channel
  q = ch.queue("", exclusive: true)
  ch.default_exchange.publish("x", routing_key: q.name)
  pass!("write-only: publish works")
  begin
    ch.queue_bind(q.name, "amq.direct", routing_key: "test-key")
    fail!("write-only: bind rejected", "bind succeeded")
  rescue Bunny::AccessRefused
    pass!("write-only: bind rejected")
  end
  conn.close
rescue => e
  fail!("write-only: scope test", e.message)
end

def test_amqp_configure_only(opts, token_endpoint)
  puts "\n== AMQP: configure-only scope =="
  token = get_token(opts, token_endpoint, "configure:%2F/*")
  conn = amqp_connect(opts[:amqp], token)
  ch = conn.create_channel
  ch.queue("", exclusive: true)
  pass!("configure-only: declare works")
  conn.close
rescue Bunny::PossibleAuthenticationFailureError
  pass!("configure-only: connection rejected (acceptable)")
rescue => e
  fail!("configure-only: declare works", e.message)
end

def test_amqp_tags(opts, token_endpoint)
  puts "\n== AMQP: tag scopes =="
  unless opts[:http]
    skip!("tags", "no --http provided")
    return
  end
  %w[administrator monitoring management policymaker impersonator].each do |tag|
    token = get_token(opts, token_endpoint, "tag:#{tag} read:%2F/* write:%2F/* configure:%2F/*")
    uri = URI("#{opts[:http]}/api/whoami")
    req = Net::HTTP::Get.new(uri)
    req.basic_auth("unused", token)
    resp = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == "https",
                           open_timeout: 5, read_timeout: 5) { |http| http.request(req) }
    if resp.is_a?(Net::HTTPSuccess)
      raw_tags = JSON.parse(resp.body).fetch("tags", "")
      tags = raw_tags.is_a?(Array) ? raw_tags.map(&:to_s) : raw_tags.to_s.split(",").map(&:strip)
      found = tags.any? { |t| t.downcase.include?(tag.downcase) }
      check("tag:#{tag} in whoami", found, "tags=#{tags}")
    else
      fail!("tag:#{tag} in whoami", "HTTP #{resp.code}")
    end
  rescue => e
    fail!("tag:#{tag} in whoami", e.message)
  end
end

def test_amqp_expired_token(opts, token_endpoint)
  puts "\n== AMQP: token expiration =="
  token = get_token(opts, token_endpoint, "read:%2F/* write:%2F/* configure:%2F/*")
  tampered = tamper_token_expiry(token)
  unless tampered
    skip!("amqp tampered expired token", "could not parse token")
    return
  end
  conn = amqp_connect(opts[:amqp], tampered)
  fail!("amqp tampered expired token rejected", "connected")
  conn.close
rescue Bunny::PossibleAuthenticationFailureError, Bunny::TCPConnectionFailedForAllHosts
  pass!("amqp tampered expired token rejected")
rescue => e
  fail!("amqp tampered expired token rejected", e.message)
end

def test_amqp_refresh(opts, token_endpoint)
  puts "\n== AMQP: token refresh =="
  token1 = get_token(opts, token_endpoint, "read:%2F/* write:%2F/* configure:%2F/*")
  conn = amqp_connect(opts[:amqp], token1)
  unless conn.respond_to?(:update_secret)
    skip!("update_secret", "bunny version does not support it")
    conn.close
    return
  end
  token2 = get_token(opts, token_endpoint, "read:%2F/* write:%2F/* configure:%2F/*")
  conn.update_secret(token2, "refresh")
  ch = conn.create_channel
  q = ch.queue("", exclusive: true)
  ch.default_exchange.publish("refreshed", routing_key: q.name)
  sleep 0.1
  _di, _props, body = q.pop
  check("amqp token refresh", body == "refreshed", "body=#{body.inspect}")
  conn.close
rescue => e
  fail!("amqp token refresh", e.message)
end

# ── MQTT tests ────────────────────────────────────────────────────────────────

def test_mqtt_publish_subscribe(opts, token_endpoint)
  puts "\n== MQTT: publish & subscribe =="
  unless opts[:mqtt]
    skip!("mqtt publish+subscribe", "no --mqtt provided")
    return
  end
  token = get_token(opts, token_endpoint, "read:%2F/* write:%2F/* configure:%2F/*")
  client = mqtt_connect_client(opts[:mqtt], token, client_id: "oauth-mqtt-pubsub")
  pass!("mqtt connect")

  received = nil
  client.subscribe("oauth/test/pubsub")
  Thread.new do
    sleep 0.5
    client.publish("oauth/test/pubsub", "mqtt-hello", false, 1)
  end
  _topic, message = client.get
  received = message
  check("mqtt publish+subscribe", received == "mqtt-hello", "received=#{received.inspect}")
  client.disconnect
rescue => e
  fail!("mqtt publish+subscribe", e.message)
end

def test_mqtt_read_only(opts, token_endpoint)
  puts "\n== MQTT: read-only scope =="
  unless opts[:mqtt]
    skip!("mqtt read-only", "no --mqtt provided")
    return
  end
  token_ro = get_token(opts, token_endpoint, "read:%2F/*")
  client_ro = mqtt_connect_client(opts[:mqtt], token_ro, client_id: "oauth-mqtt-ro")
  pass!("mqtt read-only: connects")

  # Subscribe should work (has read)
  client_ro.subscribe("oauth/test/ro")
  pass!("mqtt read-only: subscribe works")

  # Publish should cause the broker to disconnect the client (no write permission)
  client_ro.publish("oauth/test/ro", "ro-should-not-arrive", false, 1)
  begin
    Timeout.timeout(2) do
      client_ro.get # should raise because broker closes the connection
    end
    fail!("mqtt read-only: publish rejected", "publish did not cause disconnect")
  rescue MQTT::ProtocolException, Errno::ECONNRESET, EOFError, Timeout::Error
    pass!("mqtt read-only: publish rejected")
  end
rescue MQTT::ProtocolException, Errno::ECONNRESET, EOFError => e
  pass!("mqtt read-only: publish rejected (#{e.message})")
rescue => e
  fail!("mqtt read-only", e.message)
end

def test_mqtt_write_only(opts, token_endpoint)
  puts "\n== MQTT: write-only =="
  unless opts[:mqtt]
    skip!("mqtt write-only", "no --mqtt provided")
    return
  end
  token_wo = get_token(opts, token_endpoint, "write:%2F/* configure:%2F/*")
  client_wo = mqtt_connect_client(opts[:mqtt], token_wo, client_id: "oauth-mqtt-wo")

  # Publish should work (has write)
  client_wo.publish("oauth/test/wo", "wo-message", false, 1)
  pass!("mqtt write-only: publish works")

  # Subscribe should cause the broker to disconnect the client (no read permission)
  client_wo.subscribe("oauth/test/wo")
  begin
    Timeout.timeout(2) do
      client_wo.get # should raise because broker closes the connection
    end
    fail!("mqtt write-only: subscribe rejected", "subscribe did not cause disconnect")
  rescue MQTT::ProtocolException, Errno::ECONNRESET, EOFError, Timeout::Error
    pass!("mqtt write-only: subscribe rejected")
  end
rescue MQTT::ProtocolException, Errno::ECONNRESET, EOFError => e
  pass!("mqtt write-only: subscribe rejected (#{e.message})")
rescue => e
  fail!("mqtt write-only", e.message)
end

def test_mqtt_configure_only(opts, token_endpoint)
  puts "\n== MQTT: configure-only scope =="
  unless opts[:mqtt]
    skip!("mqtt configure-only", "no --mqtt provided")
    return
  end
  token = get_token(opts, token_endpoint, "configure:%2F/*")
  client = mqtt_connect_client(opts[:mqtt], token, client_id: "oauth-mqtt-co")
  pass!("mqtt configure-only: connects")
  # No read or write — publish+subscribe should be ineffective
  client.publish("oauth/test/co", "co-test", false, 1)
  client.subscribe("oauth/test/co")
  received = []
  begin
    Timeout.timeout(2) do
      _topic, message = client.get
      received << message
    end
  rescue Timeout::Error
    # expected
  end
  check("mqtt configure-only: no messages", received.empty?, "received=#{received}")
  client.disconnect
rescue MQTT::ProtocolException, Errno::ECONNRESET, EOFError => e
  pass!("mqtt configure-only: connection rejected by broker (#{e.message})")
rescue => e
  fail!("mqtt configure-only", e.message)
end

def test_mqtt_tags(opts, token_endpoint)
  puts "\n== MQTT: tags =="
  unless opts[:mqtt]
    skip!("mqtt tags", "no --mqtt provided")
    return
  end
  %w[administrator management monitoring].each do |tag|
    token = get_token(opts, token_endpoint, "tag:#{tag} read:%2F/* write:%2F/* configure:%2F/*")
    client = mqtt_connect_client(opts[:mqtt], token, client_id: "oauth-mqtt-#{tag}")
    pass!("mqtt tag:#{tag} connects")
    client.disconnect
  rescue MQTT::ProtocolException, Errno::ECONNRESET, EOFError => e
    fail!("mqtt tag:#{tag} connects", e.message)
  rescue => e
    fail!("mqtt tag:#{tag} connects", e.message)
  end
end

def test_mqtt_expired_token(opts, token_endpoint)
  puts "\n== MQTT: expired token =="
  unless opts[:mqtt]
    skip!("mqtt expired token", "no --mqtt provided")
    return
  end
  token = get_token(opts, token_endpoint, "read:%2F/* write:%2F/* configure:%2F/*")
  tampered = tamper_token_expiry(token)
  unless tampered
    skip!("mqtt tampered expired token", "could not parse token")
    return
  end
  client = mqtt_connect_client(opts[:mqtt], tampered, client_id: "oauth-mqtt-expired")
  fail!("mqtt tampered expired token rejected", "connected")
  client.disconnect
rescue MQTT::ProtocolException, Errno::ECONNRESET, EOFError
  pass!("mqtt tampered expired token rejected")
rescue => e
  fail!("mqtt tampered expired token rejected", e.message)
end

def test_mqtt_refresh(opts, token_endpoint)
  puts "\n== MQTT: token refresh =="
  unless opts[:mqtt]
    skip!("mqtt token refresh", "no --mqtt provided")
    return
  end
  # MQTT 3.1.1 does not support token refresh (no update_secret equivalent).
  # The only way to refresh is to disconnect and reconnect with a new token.
  token1 = get_token(opts, token_endpoint, "read:%2F/* write:%2F/* configure:%2F/*")
  client = mqtt_connect_client(opts[:mqtt], token1, client_id: "oauth-mqtt-refresh")
  pass!("mqtt refresh: initial connect")
  client.disconnect

  token2 = get_token(opts, token_endpoint, "read:%2F/* write:%2F/* configure:%2F/*")
  client2 = mqtt_connect_client(opts[:mqtt], token2, client_id: "oauth-mqtt-refresh")
  client2.subscribe("oauth/test/refresh")
  Thread.new do
    sleep 0.5
    client2.publish("oauth/test/refresh", "refreshed", false, 1)
  end
  received = nil
  begin
    Timeout.timeout(3) do
      _topic, message = client2.get
      received = message
    end
  rescue Timeout::Error
    # no message
  end
  check("mqtt refresh: reconnect works", received == "refreshed", "received=#{received.inspect}")
  client2.disconnect
rescue => e
  fail!("mqtt token refresh", e.message)
end

# ── HTTP management tests ────────────────────────────────────────────────────

def test_http_management(opts, token_endpoint)
  puts "\n== HTTP Management API =="
  unless opts[:http]
    skip!("http", "no --http provided")
    return
  end

  # Admin
  token = get_token(opts, token_endpoint, "tag:administrator read:%2F/* write:%2F/* configure:%2F/*")
  uri = URI("#{opts[:http]}/api/overview")
  req = Net::HTTP::Get.new(uri)
  req.basic_auth("unused", token)
  resp = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == "https",
                         open_timeout: 5, read_timeout: 5) { |http| http.request(req) }
  check("admin /api/overview", resp.is_a?(Net::HTTPSuccess), "status=#{resp.code}")

  # No tag
  token_notag = get_token(opts, token_endpoint, "read:%2F/* write:%2F/* configure:%2F/*")
  req2 = Net::HTTP::Get.new(uri)
  req2.basic_auth("unused", token_notag)
  resp2 = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == "https",
                          open_timeout: 5, read_timeout: 5) { |http| http.request(req2) }
  check("no-tag denied /api/overview", %w[401 403].include?(resp2.code), "status=#{resp2.code}")
rescue => e
  fail!("http management", e.message)
end

# ── Runner ────────────────────────────────────────────────────────────────────

def run_tests(opts)
  puts "Discovering OIDC config from #{opts[:issuer]} ..."
  token_endpoint = discover_token_endpoint(opts[:issuer])

  # AMQP
  test_amqp_publish_consume(opts, token_endpoint)
  test_amqp_read_only(opts, token_endpoint)
  test_amqp_write_only(opts, token_endpoint)
  test_amqp_configure_only(opts, token_endpoint)
  test_amqp_tags(opts, token_endpoint)
  test_amqp_expired_token(opts, token_endpoint)
  test_amqp_refresh(opts, token_endpoint)

  # MQTT
  test_mqtt_publish_subscribe(opts, token_endpoint)
  test_mqtt_read_only(opts, token_endpoint)
  test_mqtt_write_only(opts, token_endpoint)
  test_mqtt_configure_only(opts, token_endpoint)
  test_mqtt_tags(opts, token_endpoint)
  test_mqtt_expired_token(opts, token_endpoint)
  test_mqtt_refresh(opts, token_endpoint)

  # HTTP
  test_http_management(opts, token_endpoint)

  puts
  puts "=" * 50
  puts "Results: #{$pass_count} passed, #{$fail_count} failed, #{$skip_count} skipped"
  puts "=" * 50
  $fail_count == 0
end

# ── CLI ───────────────────────────────────────────────────────────────────────

opts = {}

OptionParser.new do |p|
  p.banner = <<~BANNER
    LavinMQ OAuth2 integration tests (AMQP + MQTT)

    Usage: ruby #{$PROGRAM_NAME} [options]

    Example with Auth0:
      ruby #{$PROGRAM_NAME} \\
        --issuer https://dev-xxx.us.auth0.com \\
        --client-id abc \\
        --client-secret def \\
        --audience lavinmq \\
        --amqp amqp://127.0.0.1:5672 \\
        --mqtt 127.0.0.1:1883 \\
        --http http://127.0.0.1:15672

  BANNER

  p.on("--issuer URL",        "OIDC issuer URL (required)")         { |v| opts[:issuer] = v }
  p.on("--client-id ID",      "OAuth2 client ID (required)")        { |v| opts[:client_id] = v }
  p.on("--client-secret SEC", "OAuth2 client secret (required)")    { |v| opts[:client_secret] = v }
  p.on("--amqp URL",          "AMQP URL (required)")                { |v| opts[:amqp] = v }
  p.on("--mqtt HOST:PORT",    "MQTT host:port")                     { |v| opts[:mqtt] = v }
  p.on("--http URL",          "Management HTTP URL")                { |v| opts[:http] = v }
  p.on("--audience AUD",      "Token audience (required by Auth0)") { |v| opts[:audience] = v }
  p.on("--scope-prefix PFX",  "Scope prefix (e.g. 'lavinmq.')")    { |v| opts[:scope_prefix] = v }
end.parse!

%i[issuer client_id client_secret amqp].each do |key|
  unless opts[key]
    $stderr.puts "Missing required option: --#{key.to_s.tr('_', '-')}"
    exit 1
  end
end

ok = run_tests(opts)
exit(ok ? 0 : 1)
