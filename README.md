Scripts testing OAuth2.0 in LavinMQ

## Example usage
```
ruby test_oauth2.rb \
    --issuer https://my-oidc-provider.example.com \
    --client-id my-client \
    --client-secret my-secret \
    --amqp amqp://127.0.0.1:5672 \
    --mqtt 127.0.0.1:1883 \
    --http http://127.0.0.1:15672 \
    --audience lavinmq \
    --scope-prefix lavinmq.
```
  **Required flags:** `--issuer`, `--client-id`, `--client-secret`, `--amqp`. Optional: `--mqtt`, `--http`, `--audience`, `--scope-prefix`.

  Prerequisites: `gem install bunny mqtt`
