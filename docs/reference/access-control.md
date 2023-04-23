Scoutr provides full access control over the endpoints a set of users is permitted to call and the output that is
returned. This is done using field filters, field exclusions, and permitted endpoints, which are outlined in the next
section.

This access control functionality is implemented at both a user and a group level. A user can be a member of zero or
more groups. The implementation of [auth identifiers](#auth-identifier) and [groups](#groups) is outlined in their
respective sections.

Refer to the [Authentication](../authentication) section to learn about the supported authentication types.

## Field filters

Field filters are used to perform pre-filtering of the data before it gets returned to the user and to affect what
records users are able to manipulate.

**Syntax**

Each field filter should be a list of objects. Each item in this list must be structured as:

```json
{
    "field": "name of the field to perform filter against",
    "operator": "optional operator. this defaults to 'eq'",
    "value": "value to filter"
}
```

!!! info
    The supported operators are listed on the [filtering page](../filtering#magic-operators). If you specify an invalid
    operator, an error will be returned whenever that user attempts to perform a request.

When using the `in` operator to check multiple values, the `value` field should be formatted as an array like below:
```json
{
    "field": "name of the field to perform filter against",
    "operator": "in",
    "value": [
        "value1",
        "value2",
        "value3"
    ]
}
```

### Types of field filters
There are four types of field filters: read, create, update, and delete filters.

#### Read Filters
Read filters are used to configure what data is returned from the data table, prior to any user-requested filters.
Refer to the [filter merging](#filter-merging) section for more information on how read filters work.

#### Create Filters
Create filters are used to configure conditions that must be satisfied for a user to create a record in the data table.
This ensures that a user has permission to set the fields they have included in their request body. If the filter
criteria fails, then the request will be denied with an Unauthorized error. The final step is to run
[field validation](../validation).

The checks are performed as follows:

1. Ensure the user has permissions to set the fields they have included in their request body using the values in
    `exclude_fields`. The idea is that if the user does not have permission to view a field, they also do not have
    permission to set the value of that field. If any matches are found, the request will be denied.
2. Run [field validation](../validation) as normal
3. Run the `create_filters` against the request body. This will determine if the user has permission to create a record
    with the values they have specified. If the filter criteria fails, the request will be denied with an Unauthorized
    error stating which fields have invalid values.

##### Example

If a user has these create filters:

```json
{
    "create_filters": [
        {
            "field": "product",
            "operator": "ne",
            "value": "Standard"
        }
    ]
}
```

And they attempt to create the below record:

```json
{
    "name": "test",
    "product": "Standard"
}
```

Their request would be denied because `product` is set to "Standard", but the create filters require that it be not
equal to "Standard". If the request were changed to the following, it would be accepted:

```json
{
    "name": "test",
    "product": "Limited"
}
```

!!! note
    Users still need permission to access the create endpoint using [`permitted_endpoints`](#permitted-endpoints). If
    they cannot access the endpoint, their request would be denied before any filter criteria is evaluated.

#### Update Filters
Update filters are used to configure the conditions that must be satisfied for a user to update a record in the data
table. This ensures that a user has permission to set the fields they have included in their request body. If the filter
criteria fails, then the request will be denied with an Unauthorized error.

The checks are performed as follows:

1. Use `update_filters` to determine if the user has permission to access the specified record. If no records are
    returned from the data table, then the record either does not exist or the user does not have permission to update
    it and a Not Found error will be returned. However, if a record is returned, then the user has permissions to update
    the record.
2. Use `update_fields_permitted`,  `update_fields_restricted`, and `exclude_fields` to determine if the user has
    permissions to update the fields they specified in the request body. If either of these criteria fail, the request
    will be denied with an Unauthorized error.
3. Take the contents of the requested item from the data table and merge the user's desired changes with that item.
    Then, run the `update_filters` against this combined record. This will determine if the user has permission to
    make the changes they are requesting to the object. If the filter criteria fails, the request will be denied with
    an Unauthorized error stating which fields have invalid values.
4. Finally, [field validation](../validation) runs as normal.

##### Example
Let's say the user has these permissions:

```json
{
    "update_filters": [
        {
            "field": "product",
            "operator": "eq",
            "value": "a"
        }
    ]
}
```

The record they are trying to modify in the database looks like:

```json
{
    "product": "a",
    "approved": false
}
```

If the user tries to perform the below update request:

```json
{
    "product": "b",
    "approved": true
}
```

Then this request will be denied because the `update_filters` do not permit the user to modify the `product` key to any
value that is not equal to "a". However, this update would be permitted because the `product` key is not being modified
from its current value of "a":

```json
{
    "approved": true,
    "reason": "approved by user"
}
```

Now, let's say that the same user was trying to update the below record:

```json
{
    "product": "b",
    "approved": false
}
```

If the user tried to perform the below request, it would be denied because they do not have permission to update an
item where the `product` key is **not equal** to "a":

```json
{
    "approved": true
}
```

#### Delete Filters
Update filters are used to configure the conditions that must be satisfied for a user to delete a record in the data
table. If the filter criteria fails, then the request will be denied with an Unauthorized error.

##### Example

Let's say the user has these permissions:

```json
{
    "delete_filters": [
        {
            "field": "product",
            "operator": "eq",
            "value": "a"
        }
    ]
}
```

The record they are trying to delete in the database looks like:

```json
{
    "product": "a",
    "approved": false
}
```

If the user tries to perform a delete request against that record, it would be permitted because the `product` key is
equal to "a". However, if the user attempted to perform a delete request against the below record, it would be denied
because the `product` key is **not equal** to "a":

```json
{
    "product": "b",
    "approved": false
}
```

### Filter Merging

When a user is assigned multiple filters that target the same key, they are merged together using an `OR` operation.
Then, those filters will be combined together with the filters for other keys using an `AND` operation.

For example, if a user has the below read filters:

```json
{
    "read_filters": [
        // Inherited from group-a
        {
            "field": "product",
            "operator": "contains",
            "value": "Standard"
        },
        // Inherited from group-b
        {
            "field": "product",
            "operator": "ne",
            "value": "Standard Elite"
        },
        // Inherited from group-c
        {
            "field": "product_status",
            "value": "Active"
        },
        // Inherited from user
        {
            "field": "target_audience",
            "value": "Global"
        }
    ]
}
```

The below filter expression would be generated:

```sql
(
    product CONTAINS "Standard" OR product != "Standard Elite"
)
AND product_status = "Active"
AND target_audience = "Global"
```

These filters will be further merged together with any filters the user specified using another `AND` operation. For
instance, if the user performed these filters on their request:

```
GET /products/?company=ABC&product_status=Pending
```

The generated filter expression would be:

```sql
(
    product CONTAINS "Standard" OR product != "Standard Elite"
)
AND product_status = "Active"
AND target_audience = "Global"
AND company = "ABC"
AND product_status = "Pending"
```

This will actually produce no results because the filters `product_status = "Active"` and `product_status = "Pending"`
are conflicting. The user is intentionally unable to override any filters defined by the administrator.

If the user removed their filter for `product_status = "Pending"` and only filtered on `company`:

```
GET /products/?company=ABC
```

The generated filter expression would be:
```sql
(
    product CONTAINS "Standard" OR product != "Standard Elite"
)
AND product_status = "Active"
AND target_audience = "Global"
AND company = "ABC"
```


And any results that met that criteria would be returned

## Field exclusions

Field exclusions allow for excluding one or more fields from the output of all queries. These fields are from any output
during the post-processing phase of all queries. Additionally, if a user attempts to create or update an item that
contains a field from this list, the operation will be denied.

**Syntax**

```json
[
    "field1",
    "field2"
]
```

## Permitted endpoints

Before taking any action, every call is validated to ensure the user has permissions to perform the call. For
convenience, regular expressions can be used within the `endpoint` field.

**Syntax**

```json
[
    {"method": "GET|POST|PUT|DELETE", "endpoint": "/endpoint"},
    {"method": "GET|POST|PUT|DELETE", "endpoint": "^/endpoint2/.+$"}
]
```

## Groups

A group object be made up of:

- `id` - Identifier for the group
- `permitted_endpoints` - Optional list of permitted endpoints
- `read_filters` - Optional list of read filters
- `create_filters` - Optional list of create filters
- `update_filters` - Optional list of update filters
- `delete_filters` - Optional list of delete filters
- `exclude_fields` - Optional list of field exclusions
- `update_fields_permitted` - Optional list of the only fields that can be updated
- `update_fields_restricted` - Optional list of fields to restrict updates for

The name of the group table must be passed in to the constructor.

### Example
```json
{
    "id": "read-only",
    "permitted_endpoints": [
        {
            "endpoint": "^/account/.+$",
            "method": "GET"
        },
        {
            "endpoint": "^/accounts.*$",
            "method": "GET"
        },
        {
            "endpoint": "^/search/.+$",
            "method": "POST"
        }
    ],
    "exclude_fields": [
        "field1"
    ],
    "update_fields_permitted": [
        "field4"
    ],
    "update_fields_restricted": [
        "field5"
    ],
    "read_filters": [
        {
            "field": "field2",
            "value": "value1"
        },
        {
            "field": "field3",
            "operator": "in",
            "value": [
                "value2",
                "value3"
            ]
        }
    ]
}
```

## Auth Identifier

An auth record is made up of:

- `id` - Identifier for the user/auth record
- `username` - Username for this user. This is optional when using OIDC since the information is filled by OIDC.
- `name` - Username for this user. This is optional when using OIDC since the information is filled by OIDC.
- `email` - Email for this user. This is optional when using OIDC since the information is filled by OIDC.
- `groups` - Optional list of groups this user is a member of
- `permitted_endpoints` - Optional list of permitted endpoints
- `read_filters` - Optional list of read filters
- `create_filters` - Optional list of create filters
- `update_filters` - Optional list of update filters
- `delete_filters` - Optional list of delete filters
- `exclude_fields` - Optional list of field exclusions
- `update_fields_permitted` - Optional list of the only fields that can be updated
- `update_fields_restricted` - Optional list of fields to restrict updates for

### Types

There are three types of accepted authentication identifiers:

- USERNAME
- OIDC_GROUP
- API_KEY

Though not required, it is recommended for each object type to have a `type` key that corresponds to its
authentication type (OIDC_GROUP, USERNAME, or API_KEY).

The field requirements for each object type are outlined in the following sections

#### USERNAME
- id (primary key) - this is the user's username

Though not required, it is recommended to also include a `name` field containing the user's full name to make it
easier to identify the user at a glance.

#### OIDC_GROUP
- id (primary key) - this is expected to be the group id

Though not required, it is recommended to also include a `name` field containing the group's display name to make it
easier to identify the group at a glance.

If a user is a member of more than one OIDC group, the permissions granted by each configured group will be combined
together to generate the effective permissions applied to the user.

#### API_KEY

- id (primary key) - this is the api key id
- name
- username
- email

### Groups

Optionally, each auth object can include a `groups` object, which should be a list of group ids that the user is a
member of:
```json
{
    "groups": [
        "read-only",
        "view-audit-logs"
    ]
}
```

Any permissions defined in the groups are combined together to make up the user's permissions. In addition, the same
permissions that a group defines (`read_filters`, `create_filters`, `update_filters`, `delete_filters`,
`exclude_fields`, `update_fields_permitted`, `update_fields_restricted`, `permitted_endpoints`) can be expressed at the
user level. These permissions will be combined together with the permissions outlined in the groups the user is a member
of. Permissions defined at the user level **DO NOT** override those specified at the group level - they are combined.

If a user is a member of multiple OIDC groups, the permissions are combined as explained in the
[filter merging](#filter-merging) section.

### Example

```json
{
    "id": "johndoe",
    "type": "API_KEY",
    "username": "johndoe",
    "name": "John Doe",
    "email": "john@doe.com",
    "groups": ["read-only", "standard-product-only"],
    "read_filters": [
        {
            "field": "product",
            "value": "Limited"
        }
    ]
}
```

## Audit Logs

For every authorized, successful call to the API, an entry will be logged in the audit log table. Each record will
follow the below format:

```json
{
  "action": "CREATE|UPDATE|DELETE|GET|LIST|SEARCH|{CUSTOM-ACTION}",
  "body": {
    "key": "value"
  },
  "method": "HTTP method from API gateway",
  "path": "/endpoint/path",
  "path_params": {
    "key": "value"
  },
  "query_params": {
    "key": "value"
  },
  "resource": {
    "key": "value"
  },
  "time": "2019-10-04T18:44:30.166635",
  "user": {
    "api_key_id": "ID",
    "name": "John Doe",
    "source_ip": "1.2.3.4",
    "username": "222222222",
    "user_agent": "curl"
  }
}
```

The following fields may not be included or may not have values for all types of actions:

- body
- query_params
- path_params
- resource
