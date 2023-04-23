# About

Scoutr was built as a means to provide a simple way to put an API in front of a NoSQL backend and ensure full
role-based access control (RBAC) integration with audit logging.

A Go implementation is available at [scoutr-go](https://github.com/MichaelPalmer1/scoutr-go).

## Features

### Pre-Filtering
The most powerful part of Scoutr is the [pre-filtering](reference/filtering) that can be applied to users or groups.
This enables you to store a large amount of data and only grant users access to a subset of this information.

### Post-Filtering
If your data backend contains some fields that are sensitive and you do not want exposed to all of your users, you can
configure [field exclusions](reference/access-control#field-exclusions) to strip those fields from the output.

### Endpoint Restriction
You can [restrict](reference/access-control#permitted-endpoints) which endpoints a user is permitted to access using
regular expressions combined with specific HTTP methods.

### Auditing
Every request is [logged](reference/access-control#audit-logs) into an audit table with full details about the request.
