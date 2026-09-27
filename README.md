# PGP OIDC

PGP OIDC (or as branded on the pages as "ITOJ OIDC") is an OpenID Connect provider service made to function as a stateless Cloudflare Worker!

The service supports you passing the raw URL to a trusting OIDC RP (Relying Party) to select the key fingerprint to use manually, or generating your own hinted URL at the base domain too!

This service currently supports the `email`, `openid` and `profile` scopes, with the `sub`, `email`, `email_verified`, and `name` claims!

## Deploying

To deploy this project to your own site, simply use `wrangler deploy`!
