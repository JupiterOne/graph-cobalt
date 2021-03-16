# Development

Cobalt REST API:
https://app.swaggerhub.com/apis/CobaltLab/Cobalt_Public_API/1.3.0

Short version for the 2-step authentication process:

1. Generate an API key under Profile in your Cobalt account.
2. That key is used to Bearer authorize to the /orgs endpoint, which returns an
   object with an orgToken.
3. orgToken is then used to get anything more detailed than /orgs (eg.
   /findings, /pentests, etc).

More details below under Authentication.

## Prerequisites

Nothing special. Standard tools.

## Authentication

The API is read-only. To use it manually from Swagger:

1. From the profile dropdown on your Cobalt account, create a
   [personal API token](https://app.cobalt.io/settings/api-token).
2. With your token copied locally (once you leave the page you won't be able to
   copy it), you can head to
   [Swagger](https://app.swaggerhub.com/apis/CobaltLab/Cobalt_Public_API/1.3.0).
3. Make sure to point to Production (https://api.cobalt.io) from the drop-down
4. Authorize with your API token in the API_KEY_AUTH field.
5. Eexecute the /orgs endpoint via the Execute button on the API page.
6. Note the organization token.
7. Return back to the Authorize section and add the org token and Authorize that
   as part of your OrgToken (i.e. X-Org-Token) header. Now, all subsequent
   requests to /assets, /findings, /pentests, etc will be scoped to your
   personal API token and the appropriate org token

To use the API via code:

1. From the profile dropdown on your
   [Cobalt account](https://app.cobalt.io/users/sign_in), generate an
   [API key](https://app.cobalt.io/settings/api-token).
2. Copy the API key locally once it is displayed, because you won't be able to
   after you leave the generation page.
3. Execute https://api.cobalt.io/orgs with a header included of
   `'Authorization': 'Bearer API_KEY_AUTH'`, where API_KEY_AUTH is what you made
   on step one.
4. The reply object will include `data.data[0].resource.token`, which is a
   string for your orgToken.
5. For all other /GET requests to the API, include a header of
   `'X-Org-Token': 'ORG_TOKEN'`.
