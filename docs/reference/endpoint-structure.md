The helper methods within Scoutr assume that your API consists of the below endpoint types.

## List all records

The list all items endpoint will return a list of all items within the backend that the user has permission to see
and that meet any specified filter criteria.

### Serverless Example
```yaml
list:
  handler: endpoints.list.lambda_handler
  events:
    - http:
        path: items
        method: get
        private: true
```

### Implementation Example

```python
import json
import os

from scoutr.exceptions import HttpException
from scoutr.helpers.api_gateway import build_api_gateway_request, handle_http_exception
from scoutr.models.config import Config
from scoutr.providers.aws import DynamoAPI

try:
    import sentry_sdk
except ImportError:
    from scoutr.utils import mock_sentry
    sentry_sdk = mock_sentry

def lambda_handler(event, context):
    config = Config(
        data_table=os.getenv('TableName'),
        auth_table=os.getenv('AuthTable'),
        group_table=os.getenv('GroupTable'),
        audit_table=os.getenv('AuditTable'),
        primary_key='id'
    )

    try:
        api = DynamoAPI(config)
        data = api.list(
            request=build_api_gateway_request(event)
        )
    except HttpException as e:
        if e.status == 500:
            sentry_sdk.capture_exception(e)
        return handle_http_exception(e)
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

    return {
        'statusCode': 200,
        'body': json.dumps(data)
    }
```

## List all unique values for a key

The list by unique key endpoint is provided as a means to display all unique values for a single search key. It is
implemented by specifying a value for the `key` argument of the `list_unique_values()` method. Additionally, if you
wish to run a custom unique function against the returned dataset, you can specify that as a callable in the
`unique_func` argument. The function should accept a `list` of `dicts` as the first argument (the data) and a
`str` (the unique key) as the second argument. It should output a `list` of `strs`. For example:

```python
def unique_values(data: List[dict], key: str) -> List[str]:
    return sorted(
        set(
            [
                item[key]
                for item in data
                if item and item[key]
            ]
        )
    )

data = api.list_unique_values(request, key='type', unique_func=unique_values)
```

### Implementation Example

```python
import json
import os

from scoutr.exceptions import HttpException
from scoutr.helpers.api_gateway import build_api_gateway_request, handle_http_exception
from scoutr.models.config import Config
from scoutr.providers.aws import DynamoAPI

try:
    import sentry_sdk
except ImportError:
    from scoutr.utils import mock_sentry
    sentry_sdk = mock_sentry

def lambda_handler(event, context):
    config = Config(
        data_table=os.getenv('TableName'),
        auth_table=os.getenv('AuthTable'),
        group_table=os.getenv('GroupTable'),
        audit_table=os.getenv('AuditTable'),
        primary_key='id'
    )

    try:
        api = DynamoAPI(config)
        data = api.list_unique_values(
            request=build_api_gateway_request(event),
            key='product'
        )
    except HttpException as e:
        if e.status == 500:
            sentry_sdk.capture_exception(e)
        return handle_http_exception(e)
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

    return {
        'statusCode': 200,
        'body': json.dumps(data)
    }
```

## Search multiple values for a single search key

The search endpoint enables users to lookup information about multiple items by utilizing a dynamic path variable
(POST `/search/{search_key}`).

For example, if you wanted to search for records that had specific `product` key, you could submit the below request:

```
POST /search/product
```

With the body:

```json
[
    "Standard",
    "Limited",
    "Deluxe"
]
```

Would return the contents of records where `product` is one of "Standard", "Limited", or "Deluxe".

### Implementation Example

```python
import json
import os

from scoutr.exceptions import HttpException
from scoutr.helpers.api_gateway import build_api_gateway_request, handle_http_exception
from scoutr.models.config import Config
from scoutr.providers.aws import DynamoAPI

try:
    import sentry_sdk
except ImportError:
    from scoutr.utils import mock_sentry
    sentry_sdk = mock_sentry

def lambda_handler(event, context):
    config = Config(
        data_table=os.getenv('TableName'),
        auth_table=os.getenv('AuthTable'),
        group_table=os.getenv('GroupTable'),
        audit_table=os.getenv('AuditTable'),
        primary_key='id'
    )

    # Get path parameters
    path_params = event['pathParameters']
    query = json.loads(event['body'])
    search_key = path_params['search_key']

    try:
        api = DynamoAPI(config)
        data = api.search(
            request=build_api_gateway_request(event),
            key=search_key,
            values=query
        )
    except HttpException as e:
        if e.status == 500:
            sentry_sdk.capture_exception(e)
        return handle_http_exception(e)
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

    return {
        'statusCode': 200,
        'body': json.dumps(data)
    }
```

## Get single item by key

If this returns more than one record, it will throw a `BadRequestException`. If no records are
returned, a `NotFoundException` will be thrown.

### Implementation Example

```python
import json
import os

from scoutr.exceptions import HttpException
from scoutr.helpers.api_gateway import build_api_gateway_request, handle_http_exception
from scoutr.models.config import Config
from scoutr.providers.aws import DynamoAPI

try:
    import sentry_sdk
except ImportError:
    from scoutr.utils import mock_sentry
    sentry_sdk = mock_sentry

def lambda_handler(event, context):
    config = Config(
        data_table=os.getenv('TableName'),
        auth_table=os.getenv('AuthTable'),
        group_table=os.getenv('GroupTable'),
        audit_table=os.getenv('AuditTable'),
        primary_key='id'
    )

    # Get item id
    item_id = event['pathParameters']['id']

    try:
        api = DynamoAPI(config)
        data = api.get(
            request=build_api_gateway_request(event),
            key='id',
            value=item_id
        )
    except HttpException as e:
        if e.status == 500:
            sentry_sdk.capture_exception(e)
        return handle_http_exception(e)
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

    return {
        'statusCode': 200,
        'body': json.dumps(data)
    }
```

## Create item

Refer to the [data validation](../validation) section for more information on validation.

### Implementation Example

```python
import json
import os
import re

from scoutr.exceptions import HttpException
from scoutr.helpers.api_gateway import build_api_gateway_request, handle_http_exception
from scoutr.models.config import Config
from scoutr.providers.aws import DynamoAPI
from scoutr.utils import value_in_set

try:
    import sentry_sdk
except ImportError:
    from scoutr.utils import mock_sentry
    sentry_sdk = mock_sentry


PRODUCTS = {'a', 'b', 'c'}

VALIDATION = {
    'product': lambda value, item, existing_item: value_in_set(
        value=value,
        valid_options=PRODUCTS,
        option_name='product'
    ),
    'date': lambda value, item, existing_item: {
        'result': re.match('^\d{4}-\d{2}-\d{2}$', value),
        'message': 'Date must be formatted as YYYY-MM-DD'
    }
}

def lambda_handler(event, context):
    config = Config(
        data_table=os.getenv('TableName'),
        auth_table=os.getenv('AuthTable'),
        group_table=os.getenv('GroupTable'),
        audit_table=os.getenv('AuditTable'),
        primary_key='id'
    )

    item = json.loads(event['body'])

    try:
        api = DynamoAPI(config)
        data = api.create(
            request=build_api_gateway_request(event),
            data=item,
            validation=VALIDATION
        )
    except HttpException as e:
        if e.status == 500:
            sentry_sdk.capture_exception(e)
        return handle_http_exception(e)
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

    return {
        'statusCode': 200,
        'body': json.dumps(data)
    }
```

## Update single item by key

The `update()` method accepts a couple of arguments:

**`primary_key`**
Mapping of the primary key to value. For instance, if the table's primary key is `id`, it is expected this mapping
would be:

```python
{'id': 'value'}
```

**`data`**
Dictionary of fields to be updated

**`validation`**
Dictionary of fields to perform validation against. Refer to the [data validation](../validation) section for more
information.

**`condition`**
Conditional expression to apply on updates. This should be an instance of boto3's
[`ConditionExpression`](https://www.programcreek.com/python/example/103724/boto3.dynamodb.conditions.Attr). If the
condition expression does not pass, a `BadRequestException` will be thrown.

**`condition_failure_message`**

By default, if the condition expression does not pass, it will return an error to the user stating
"Conditional check failed". However, if this parameter is supplied, it will be returned to the user instead.

### Implementation Example

```python
import json
import os
import re

from scoutr.exceptions import HttpException
from scoutr.helpers.api_gateway import build_api_gateway_request, handle_http_exception
from scoutr.models.config import Config
from scoutr.providers.aws import DynamoAPI
from scoutr.utils import value_in_set

try:
    import sentry_sdk
except ImportError:
    from scoutr.utils import mock_sentry
    sentry_sdk = mock_sentry


PRODUCTS = {'a', 'b', 'c'}

VALIDATION = {
    'product': lambda value, item, existing_item: value_in_set(
        value=value,
        valid_options=PRODUCTS,
        option_name='product'
    ),
    'date': lambda value, item, existing_item: {
        'result': re.match('^\d{4}-\d{2}-\d{2}$', value),
        'message': 'Date must be formatted as YYYY-MM-DD'
    }
}

def lambda_handler(event, context):
    config = Config(
        data_table=os.getenv('TableName'),
        auth_table=os.getenv('AuthTable'),
        group_table=os.getenv('GroupTable'),
        audit_table=os.getenv('AuditTable'),
        primary_key='id'
    )

    data = json.loads(event['body'])

    try:
        api = DynamoAPI(config)
        data = api.update(
            request=build_api_gateway_request(event),
            data=data,
            validation=VALIDATION
        )
    except HttpException as e:
        if e.status == 500:
            sentry_sdk.capture_exception(e)
        return handle_http_exception(e)
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

    return {
        'statusCode': 200,
        'body': json.dumps(data)
    }
```

## Delete single item by key

**`primary_key`**
Mapping of the primary key to value. For instance, if the table's primary key is `id`, it is expected this mapping
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

### Implementation Example

```python
import json
import os
import re

from scoutr.exceptions import HttpException
from scoutr.helpers.api_gateway import build_api_gateway_request, handle_http_exception
from scoutr.models.config import Config
from scoutr.providers.aws import DynamoAPI
from scoutr.utils import value_in_set

try:
    import sentry_sdk
except ImportError:
    from scoutr.utils import mock_sentry
    sentry_sdk = mock_sentry


PRODUCTS = {'a', 'b', 'c'}

VALIDATION = {
    'product': lambda value, item, existing_item: value_in_set(
        value=value,
        valid_options=PRODUCTS,
        option_name='product'
    ),
    'date': lambda value, item, existing_item: {
        'result': re.match('^\d{4}-\d{2}-\d{2}$', value),
        'message': 'Date must be formatted as YYYY-MM-DD'
    }
}

def lambda_handler(event, context):
    config = Config(
        data_table=os.getenv('TableName'),
        auth_table=os.getenv('AuthTable'),
        group_table=os.getenv('GroupTable'),
        audit_table=os.getenv('AuditTable'),
        primary_key='id'
    )

    # Get item id
    item_id = event['pathParameters']['id']

    try:
        api = DynamoAPI(config)
        data = api.delete(
            request=build_api_gateway_request(event),
            primary_key={'id': item_id}
        )
    except HttpException as e:
        if e.status == 500:
            sentry_sdk.capture_exception(e)
        return handle_http_exception(e)
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

    return {
        'statusCode': 200,
        'body': json.dumps(data)
    }
```

## List all audit logs

This endpoint enables users to view and filter all of the audit logs. Note that field filter permissions do not apply to
audit logs, but the `permitted_endpoint` permissions still do.

### Implementation Example

```python
import json
import os

from scoutr.exceptions import HttpException
from scoutr.helpers.api_gateway import build_api_gateway_request, handle_http_exception
from scoutr.models.config import Config
from scoutr.providers.aws import DynamoAPI

try:
    import sentry_sdk
except ImportError:
    from scoutr.utils import mock_sentry
    sentry_sdk = mock_sentry

def lambda_handler(event, context):
    config = Config(
        data_table=os.getenv('TableName'),
        auth_table=os.getenv('AuthTable'),
        group_table=os.getenv('GroupTable'),
        audit_table=os.getenv('AuditTable'),
        primary_key='id'
    )

    # Build request
    request = build_api_gateway_request(event)

    # Validate item id
    item = request.path_params.get('item')
    if item:
        param_overrides = {'resource.id': item}
    else:
        param_overrides = {}

    try:
        api = DynamoAPI(config)
        data = api.list_audit_logs(
            request=request,
            param_overrides=param_overrides
        )
    except HttpException as e:
        if e.status == 500:
            sentry_sdk.capture_exception(e)
        return handle_http_exception(e)
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

    return {
        'statusCode': 200,
        'body': json.dumps(data)
    }
```

## View item history

The history endpoint utilizes the audit logs to reconstruct snapshots of a record over time. A sample output is shown
below:

```json
[
    {
        "data": {
            "product": "a",
            "active_date": "2019-12-17",
            "status": "Suspended"
        },
        "time": "2020-01-01T16:10:32.399907"
    },
    {
        "data": {
            "product": "a",
            "active_date": "2019-12-17",
            "status": "Active"
        },
        "time": "2019-12-01T19:04:42.054592"
    },
    {
        "data": {
            "product": "a",
            "status": "Created"
        },
        "time": "2019-01-01T00:00:00.000769"
    }
]
```

### Implementation Example

```python
import json
import os

from scoutr.exceptions import HttpException
from scoutr.helpers.api_gateway import build_api_gateway_request, handle_http_exception
from scoutr.models.config import Config
from scoutr.providers.aws import DynamoAPI

try:
    import sentry_sdk
except ImportError:
    from scoutr.utils import mock_sentry
    sentry_sdk = mock_sentry

def lambda_handler(event, context):
    config = Config(
        data_table=os.getenv('TableName'),
        auth_table=os.getenv('AuthTable'),
        group_table=os.getenv('GroupTable'),
        audit_table=os.getenv('AuditTable'),
        primary_key='id'
    )

    # Get parameters
    item = event['pathParameters']['id']

    try:
        api = DynamoAPI(config)
        data = api.history(
            request=build_api_gateway_request(event),
            key='id',
            value=item
        )
    except HttpException as e:
        if e.status == 500:
            sentry_sdk.capture_exception(e)
        return handle_http_exception(e)
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

    return {
        'statusCode': 200,
        'body': json.dumps(data)
    }
```