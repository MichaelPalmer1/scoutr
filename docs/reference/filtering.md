There are two levels of filtering that are supported:

- Path-based filtering
- Query string-based filtering

Most of the time, query string-based filtering will serve the purpose unless you want your URLs to look a specific way,
in which path-based filtering can be advantageous:


To search for records where `product` is equal to "a":

```
/endpoint/product/a
```

## Dynamic path filters


The `list` action supports dynamic path filtering. When `search_key` and `search_value` are passed into
the method as path parameters in the `Request`, it will dynamically modify the path parameters to construct a search
filter where

```
search_key = search_value
```

To configure this, setup path parameters on the resource:
```
/endpoint/{search_key}/{search_value}
```

When using [serverless.yml](https://www.serverless.com/) for [API Gateway](https://aws.amazon.com/api-gateway/):

```yaml
events:
  - http:
      path: endpoint
      method: get
      private: true
  - http:
      path: endpoint/{search_key}/{search_value}
      method: get
      private: true
```

When using the dynamic path filters, there is no need to construct additional endpoints that support filtering by a
specific key. However, using this method provides no limitations over what fields can be used as a filter. If that is a
concern for your API, you will need to construct static path filters.

## Static path filters

Static path filters can be constructed in a similar manner to the dynamic path filters, except that the search key is
manually specified:

```
/endpoint/status/{status}
```

In order to properly work, the path variable must _exactly_ match the key in the backend table that you want to perform
the filter against.

## Query String Filters

In addition to path filters, query string filtering is also supported. The `Request` accepts a `query_params` argument.
Each querystring should be a `field_name=search_value` format:

```
/endpoint?status=Active&field3=value2
```

Path parameters **always** take precedence over querystring parameters. The below query:

```
/endpoint/field2/value1?status=Active&field2=value2
```

Would result in this filter criteria:

```
field2 = value1 AND status = Active
```

### Operators

For more complex queries, querystring search supports operators that can be used to further customize how
the data is filtered.

#### Supported Operators

| Operator      | Description                              | Syntax                                                                         | Providers                                  |
|---------------|------------------------------------------|--------------------------------------------------------------------------------|--------------------------------------------|
| `eq`          | Value is equal to                        | `data=abc` OR `data__eq=abc`                                                   | All providers                              |
| `ne`          | Value is not equal to                    | `data__ne=abc`                                                                 | All providers                              |
| `in`          | Value is in list                         | `data__in=["value1", "value2"]`                                                | All providers                              |
| `notin`       | Value is not in list                     | `data__notin=["value1", "value2"]`                                             | All providers                              |
| `startswith`  | String starts with                       | `data__startswith=abc`                                                         | <ul><li>DynamoDB</li><li>MongoDB</li></ul> |
| `contains`    | Strings contains                         | `data__contains=abc`                                                           | <ul><li>DynamoDB</li><li>MongoDB</li></ul> |
| `notcontains` | String does not contain                  | `data__notcontains=abc`                                                        | <ul><li>DynamoDB</li><li>MongoDB</li></ul> |
| `exists`      | Attribute exists / not exists            | `data__exists=true` OR `data__exists=false`                                    | <ul><li>DynamoDB</li><li>MongoDB</li></ul> |
| `gt`          | Greater than                             | `data__gt=20`                                                                  | All providers                              |
| `lt`          | Less than                                | `data__lt=20`                                                                  | All providers                              |
| `gte`         | Greater than or equal                    | `data__gte=20`                                                                 | All providers                              |
| `lte`         | Less than or equal                       | `data__lte=20`                                                                 | All providers                              |
| `between`     | Value is between                         | `data__between=[10, 20]`                                                       | All providers                              |
| `length`      | Length of array is                       | `data__length=4`                                                               | All providers                              |
| `length__gt`  | Length of array is greater than          | `data__length__gt=4`                                                           | All providers                              |
| `length__gte` | Length of array is greater than or equal | `data__length__gte=4`                                                          | All providers                              |
| `length__lt`  | Length of array is less than             | `data__length__lt=4`                                                           | All providers                              |
| `length__lte` | Length of array is less than or equal    | `data__length__lte=4`                                                          | All providers                              |
| `regex`       | Regular expression                       | `data__regex=^ab.*c$`                                                          | MongoDB                                    |
| `type`        | Value is the specified type              | `data__type=array`                                                             | MongoDB                                    |
| `haselements` | Value has the specified elements         | `data__haselements=["value1", "value2"] OR data__haselements={"key": "value"}` | MongoDB                                    |

#### Usage

To use an operator, append `__operator` to the key name. For example:

To search for all items with the `field1` key containing the phrase "val"

```
/items?field1__contains=val
```

To search for all items with the `field1` key starting with the phrase "va"

```
/items?field1__startswith=va
```

Usage of all the operators is straightforward, with the exception of the `in`, `betweeen`, and `haselements` operators.
The `in` operators checks to see if the the value is included in a list of options. It should follow the JSON
list syntax:

```
/items?field1__in=["value1", "value2"]
```

The `between` operator checks to see if the value is, inclusively, between a low and high value. It should also follow
a JSON list syntax:

```
/items?num__between=[0, 3]
```

It also works for string values, such as two dates:

```
/items?date__between=["2019-01-01", "2019-12-31"]
```

To find items that have an attribute:

```
/items?name__exists=true
```

To search for items that do not have an attribute:

```
/items?name__exists=false
```

For MongoDB, `haselements` operator can be used to check if an array has one or more values:
```
/items?data__haselements=["value1", "value2"]
```

Or it can be used to check if an object has a key-value pair:

```
/items?data__haselements={"key": "value"}
```
