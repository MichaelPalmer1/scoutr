To install Scoutr, install it using Pip. Python 3.6+ is supported.

Note that dependencies are installed based on which "extra" you use. The extras are tied to each of the
[providers](../../providers):

- AWS DynamoDB: `pip install scoutr[dynamodb]`
- GCP FireStore: `pip install scoutr[firestore]`
- MongoDB: `pip install scoutr[mongo]`

Additionally, if you are using Flask as a backend instead of serverless, you should add the `flask` extra to your
installation command. For example, if you are using DynamoDB as your data backend and Flask as your API:

```
pip install scoutr[dynamodb,flask]
```

## Requirements

At minimum, three tables are required: a data table, an auth table, and a groups table. Additionally, an optional
audit log table can be used to track all API calls and changes to records in the data table. The configuration of
each table is detailed next.

### Data Table
The data table contains all of the data that is being protected and served by Scoutr. The primary key of the data table
can be anything. Your primary key can be specified in the Scoutr configuration.

### Auth Table
The auth table must have a primary key of `id`. The table name does not matter, as this is passed in during
instantiation.

### Groups Table
The groups table must have a primary key of `id`. The table name does not matter, as this is passed in during
instantiation.

### Audit Log Table
The audit log table must have a primary key of `time`. For providers that support record expiration using a TTL value,
the TTL attribute should be set to `expire_time`. The table name does not matter, as this is passed in
during instantiation. If a value is not specified, it is assumed that no audit logs should be kept.
