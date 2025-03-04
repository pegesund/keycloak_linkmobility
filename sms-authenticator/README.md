# setup

Setup "Auth methoder selector" at top level in admin

Add attributes for sending sms
Default country code should be "+47" for Norway

# Providers

- Sms only
- 2 factor with username/pw and sms

# Selecting providers

Urls:

http://localhost:8080/realms/prealm2/protocol/openid-connect/auth?client_id=account-console&response_type=code&auth_method=2fa&code_challenge_method=S256&code_challenge=gqV633dUqsLKs3Ck_bNrP7sgqBfGpHvLmRYw765rYTw&redirect_uri=http://localhost:8080/realms/prealm2/account

and

http://localhost:8080/realms/prealm2/protocol/openid-connect/auth?client_id=account-console&redirect_uri=http://localhost:8080/realms/prealm2/account&auth_method=sms

Reason 2factor needs code_challenge is that we use standard username/pw flow. With sms we need a separate flow.

