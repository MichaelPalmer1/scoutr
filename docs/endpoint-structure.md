The helper methods within Scoutr assume that your API consists of the below endpoint types.

## List all records

The list all items endpoint will return a list of all items within the backend that the user has permission to see
and that meet any specified filter criteria.

## List all unique values for a key

The list by unique key endpoint is provided as a means to display all unique values for a single search key. It is
implemented by specifying a value for the `unique_key` argument of the `list_table()` method. The simplest way to
implement this without duplicating code is to use a `UniqueKey` environment variable that defaults to a value of `None`
when the environment variable is not specified. Then, just configure your "list by unique key" Lambda with that
environment variable.

### Serverless Example
```yaml
# Unique listing of all values of the `status` key that the user is permitted to see
list-statuses:
  handler: endpoints.list.main
  events:
    - http:
        path: statuses
        method: get
        private: true
  environment:
    UniqueKey: status
```

### Implementation Example
```python
def lambda_handler(event, context):
    path_params = event.get('pathParameters', {}) or {}
    query_params = event.get('multiValueQueryStringParameters', {}) or {}
    api = DynamoAPI(
        table_name=os.getenv('TableName'),
        auth_table_name=os.getenv('AuthTable'),
        group_table_name=os.getenv('GroupTable')
    )
    data = api.list_table(
        request=build_api_gateway_request(event),
        unique_key=os.getenv('UniqueKey'),
        path_params=path_params,
        query_params=query_params
    )
```

## Search multiple values for a single search key

Lookup information about multiple items (POST `/search/{search_key}`)
```json
[
    "123456789012"
]
```

## Get single item by key

Retrieve a single record from the backend. The `get_item()` method accepts two arguments:
- `key` - the key to search by
- `value` - the value to search by

If this returns more than one record, it will throw a `BadRequestException`. If no records are
returned, a `NotFoundException` will be thrown.

## Create item

The `create()` method accepts an `item` argument, with `item` being the `dict` of the data to
be inserted. It also accepts a `field_validation` argument in order to perform validation on
all the supplied data. Refer to the [data validation](#data-validation) section for more
information.

## Update single item by key

The `update()` method accepts a couple of arguments:

**`partition_key`**
Mapping of the partition key to value. For instance, if the table's partition key is `id`, it is expected this mapping
would be:

```python
{'id': 'value'}
```

**`data`**
Dictionary of fields to be updated

**`field_validation`**
Dictionary of fields to perform validation against. Refer to the [data validation](#data-validation) section for more
information.

**`condition`**
Conditional expression to apply on updates. This should be an instance of boto3's
[`ConditionExpression`](https://www.programcreek.com/python/example/103724/boto3.dynamodb.conditions.Attr). If the
condition expression does not pass, a `BadRequestException` will be thrown.

**`condition_failure_message`**

By default, if the condition expression does not pass, it will return an error to the user stating
"Conditional check failed". However, if this parameter is supplied, it will be returned to the user instead.

## Delete single item by key

The `delete()` method accepts a couple of arguments:

**`partition_key`**
Mapping of the partition key to value. For instance, if the table's partition key is `id`, it is expected this mapping
would be:

```python
{'id': 'value'}
```

**`condition`**
Conditional expression to apply on deletions. This should be an instance of boto3's
[`ConditionExpression`](https://www.programcreek.com/python/example/103724/boto3.dynamodb.conditions.Attr). If the
condition expression does not pass, a `BadRequestException` will be thrown.

**`condition_failure_message`**

By default, if the condition expression does not pass, it will return an error to the user stating
"Conditional check failed". However, if this parameter is supplied, it will be returned to the user instead.

## List all audit logs

The `list_audit_logs()` method accepts:

**`search_params`**
Any search parameters to apply

**`query_params`**
Query parameters from API Gateway

## View item history

**`key`**
Resource key to search on

**`value`**
Resource value to search on

**`query_params`**
Query parameters from API Gateway

**`actions`**
Actions to filter on
