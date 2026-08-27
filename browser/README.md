# @domainry/identity-client

Browser client for a Runtime-mounted Domainry Identity gateway. It keeps the
short-lived access token in memory and relies on a rotating `HttpOnly; Secure;
SameSite=Lax` refresh cookie. It never writes credentials to Web Storage.
