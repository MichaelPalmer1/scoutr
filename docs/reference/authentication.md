The two types of authentication officially supported are via API Gateway or via OIDC. Helper functions have been
created for each access control type to assist with passing the correct request format into Scoutr. You can
alternatively configure a custom authenticator provider, as long as you provide the correct request information
to Scoutr.

## API Gateway
For API Gateway authentication, the request format is generated by the
[`build_api_gateway_request`](https://github.com/MichaelPalmer1/scoutr/blob/master/scoutr/helpers/api_gateway/utils.py#L7) method.

!!! note
    Only Lambda [payload version 1.0](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-integrations-lambda.html#1.0) is supported at this time.

### Example
Refer to the [example serverless endpoint](https://github.com/MichaelPalmer1/scoutr/blob/master/example/api_gateway/example/endpoints/list.py)

## OIDC
It is assumed that there is an Apache server running in front of the application that performs OIDC authentication
and passes the OIDC claims as headers.

The simplest method to setup the API is to use [Flask API](https://www.flaskapi.org/). Helper methods have been
provided to make the setup as simple as possible. The [`init_flask`](https://github.com/MichaelPalmer1/scoutr/blob/master/scoutr/helpers/flask/routes.py#L11) method
automatically generates the belows endpoints:

- GET `/user/` - Returns information about the authenticated user
- POST `/user/has-permission/` - Determine if user has permission to access an endpoint. The body of this request should
    contain `method` and `path` keys as JSON.
- GET `/<primary_list_endpoint>/` - Primary endpoint used to list data. The value of `primary_list_endpoint` is determined
    by an argument passed to `init_flask()`
- GET `/audit/` - List and search all audit logs
- GET `/audit/<item>/` - List audit logs for a particular resource
- GET `/history/<item>/` - Show history for a particular resource
- POST `/search/<search_key>/` - Search endpoint that allows searching by any key for one or more values. The body of
    this request should be a JSON list of values.

### Example
Refer to the [example flask application](https://github.com/MichaelPalmer1/scoutr/blob/master/example/flask/main.py)

## Custom
It is easy to configure a custom authentication provider as long as you use the correct `Request` format. Each of the
action-functions (i.e. `list()`, `create()`, `update()`, `delete()`, etc.) take a `request` argument that tells Scoutr
about the request and the user who performed it. To submit a custom request, make sure to provide the following inputs
correctly as shown in the below example:

```python
request = Request(
    method='POST',
    path='/products/create/',
    source_ip='1.2.3.4',
    user_agent='Postman',
    body={
        'id': '12345',
        'product': 'Standard',
        'price': 25,
        'date': '2020-01-01T00:00:00Z'
    }
    path_params: {
        'company': 'Scoutr Solutions'
    },
    query_params: {
        'status': [
            'Active',
            'Pending'
        ]
    },
    user=RequestUser(
        id='123',
        data=UserData(
            username='123',
            name='John Doe',
            email='john@doe.com',
            entitlements=['group1', 'group2', 'group3']
        )
    )
)
```

### Body
The `body` should be the JSON body of the request that comes in a `POST` or `PUT` request. For other methods, `body`
can be set to a null value.

### Path Parameters
The `path_params` should be an object mapping a path parameter key to its value.

```json
{
    "key1": "value1",
    "key2": "value2"
}
```

### Query Parameters
The `query_params` should be an object mapping a query parameter key to its values. The values must be an array, even
if there is only a single value.

```json
{
    "key": [
        "value1",
        "value2"
    ]
}
```

### Request User

The `user` key expects an instance of `RequestUser` that specifies, at minimum, an unique identifier for this
user (`id`). If your custom provider knows more information about the user
(i.e. name, email, username, OIDC group memberships), this information can be provided as `UserData` in the optional
`data` key. It is expected that if your custom provider does not know how to identify the user's data, that the
information is stored in the corresponding record in the auth table:

```json
{
    "id": "123",
    "name": "John Doe",
    "email": "john@doe.com",
    "entitlements": [
        "group-a",
        "group-b"
    ]
}
```

#### Entitlements
The `entitlements` key is used in most cases to specify that the user is a member of one or more OIDC groups. You should
specify a unique identifier in the `entitlements` array for each group membership. Once the request reaches Scoutr, it
will perform a lookup of each of these entitlement ids in the auth table to see if there are any records with that
identifier. The permissions granted by each of those entitlements in the auth table will be inherited by the user.
