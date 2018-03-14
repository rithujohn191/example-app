# example-app

This example makes use of the oidc package to fetch an access token for a particular client ID. It requires a client ID and secret of a registered OAuth2 application.

1. Set the following environment variables with client ID and client secret.

```
GOOGLE_OAUTH2_CLIENT_ID
GOOGLE_OAUTH2_CLIENT_SECRET
```

2. Run the example and navigate to http://127.0.0.1:5556.

```
go run server.go
```
You will be prompted to login via the provider if you have not done so already. If the login in successful the API will send a response containing the access token to the example application which will be displayed.
