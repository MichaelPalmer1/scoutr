## Installation

To install Scoutr, install it using Pip. Python 3.6+ is supported.

```
pip install scoutr
```

## Requirements

At minimum, two Dynamo tables are required for this to work: an auth table and a groups table. Additionally, an optional
audit log table can be used to track all API calls and changes to records in the data table. The configuration of
each table is detailed next.

### Auth Table
The auth table must have a partition key of `id`. The table name does not matter, as this is passed in during
instantiation.

### Groups Table
The groups table must have a partition key of `group_id`. The table name does not matter, as this is passed in during
instantiation.

### Audit Log Table
The audit log table must have a partition key of `time`. It should also have a TTL attribute of `expire_time`
configured. The table name does not matter, as this is passed in during instantiation. If a value is not specified, it
is assumed that no audit logs should be kept.
