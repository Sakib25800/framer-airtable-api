# Framer Airtable Plugin Backend 

CloudFlare Worker to proxy OAuth 2.0 login requests and communication tokens with the Framer Airtable plugin.


## Setup

### Environment variables

The following environment variables need to be added via the CloudFlare console or CLI.

| Name               | Details                                                                                                                 |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------- |
| CLIENT_ID          | App ID created in the providers developer console                                                                       |
| CLIENT_SECRET      | App secret key created in the providers developer console. **Do not expose** in source code or send back to the client! |
| PLUGIN_URI         | Root path of where your plugin is hosted                                                                                |
| REDIRECT_URI       | Callback path that provider will redirect to after logging in                                                           |
| AUTHORIZE_ENDPOINT | Provider endpoint path for showing the log in screen                                                                    |
| TOKEN_ENDPOINT     | Provider endpoint path for fetching and refreshing access tokens                                                        |
| SCOPE              | Provider permissions separated by a space                                                                               |

To test locally, create a `.dev.vars` file with your own `CLIENT_ID` and `CLIENT_SECRET`.

### Run locally

```sh
# Install the dependencies.
npm install

# Run the worker locally.
npm run dev
```

