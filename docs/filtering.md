There are two levels of filtering that are supported:
- Path-based filtering
- Querystring-based filtering

The `list_table()` method accepts both `path_params` and `query_params` as arguments. These are intended to
contain the values of `pathParameters` and `multiValueQueryStringParameters`, respectively, that API Gateway passed into Lambda.

## Dynamic path filters

The `list_table()` method also supports dynamic path filtering. When `search_key` and `search_value` are passed into
the method as `path_params`, it will dynamically modify the path parameters to construct a search filter where

```
search_key = search_value
```

To configure this in API Gateway, setup path parameters on the resource:
```
/endpoint/{search_key}/{search_value}
```

Or when using serverless:

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

## Querystring Filters

In addition to path filters, querystring filtering is also supported. The `list_table()` endpoint accepts all
querystrings via the `query_params` argument. Each querystring should be a `field_name=search_value` format:

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

### Magic Operators

For more complex queries, querystring search supports the below magic operations:
- `in` (value is in list)
- `notin` (value is not in list)
- `ne` (not equal)
- `startswith` (string starts with)
- `contains` (string contains)
- `notcontains` (string does not contain)
- `exists` (attribute exists)
- `gt` (greater than)
- `lt` (less than)
- `gte` (greater than or equal)
- `lte` (less than or equal)
- `between` (value is between)

To use a magic operator, append `__operator` to the key name. For example:

To search for all items with the `field1` key containing the phrase "val"

```
/items?field1__contains=val
```

To search for all items with the `field1` key starting with the phrase "va"

```
/items?field1__startswith=va
```

Usage of all the magic operators is straightforward, with the exception of the `in` and `betweeen` operators. The `in`
operators checks to see if the the value is included in a list of options. It should follow the JSON list syntax:

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
