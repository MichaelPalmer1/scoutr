All providers require that a `Config` object be passed in to tell Scoutr about your environment. The configuration
accepts the following arguments:

## Arguments

### Data Table

Name of the table that contains the data being protected by Scoutr

### Auth Table

Name of the auth table

### Groups Table

Name of the groups table

### Audit Table

Name of the audit table. If this is empty, then audit logging is disabled.

### Primary Key

Primary key in your data table

### Log Retention Days

Number of days to retain the read accesses in the Audit logs table. This requires a provider that supports a
TTL attribute to expire records.

### OIDC Username Header

Name of the OIDC header that contains the username value. Only applies when using OIDC for authentication.

### OIDC Email Header

Name of the OIDC header that contains the email value. Only applies when using OIDC for authentication.

### OIDC Groups Header

Name of the OIDC header that contains a comma-separated list of groups the user is a member of. Only applies when using
OIDC for authentication.

### OIDC Name Header

Name of the OIDC header that contains the user's name value. This can also be a tuple of strings if your OIDC provider
splits up first name and last name in separate headers. Only applies when using OIDC for authentication.

### Connection String (MongoDB only)

Connection string used to connect to MongoDB

### Database Name (MongoDB Only)

Name of the database in MongoDB to use

## Example

=== "Python"

    ```python
    config = Config(
        data_table='example-data',
        auth_table='example-auth',
        groups_table='example-groups',
        audit_table='example-audit',
        primary_key='key',
        log_retention_days=30,
        oidc_username_header='Oidc-Claim-Sub',
        oidc_email_header='Oidc-Claim-Mail',
        oidc_groups_header='Oidc-Claim-Groups',
        oidc_name_header=('Oidc-Claim-Firstname', 'Oidc-Claim-Lastname')
    )

    # For MongoDB, additional arguments are required to tell Scoutr about the MongoDB connection string and database
    mongo_config = MongoConfig(
        connection_string='mongodb://localhost',
        database='example',
        data_table='example-data',
        auth_table='example-auth',
        groups_table='example-groups',
        audit_table='example-audit',
        primary_key='key',
        log_retention_days=30,
        oidc_username_header='Oidc-Claim-Sub',
        oidc_email_header='Oidc-Claim-Mail',
        oidc_groups_header='Oidc-Claim-Groups',
        oidc_name_header=('Oidc-Claim-Firstname', 'Oidc-Claim-Lastname')
    )

    dynamo_api = DynamoAPI(config)
    firestore_api = FirestoreAPI(config)
    mongo_api = MongoAPI(mongo_config)
    ```

=== "Go"

    ```go
    config := Config{
        DataTable: "example-data",
        AuthTable: "example-auth",
        GroupsTable: "example-groups",
        AuditTable: "example-audit",
        PrimaryKey: "key",
        LogRetentionDays: 30,
        OIDCUsernameHeader: "Oidc-Claim-Sub",
        OIDCEmailHeader: "Oidc-Claim-Mail",
        OIDCGroupsHeader: "Oidc-Claim-Groups",
        OIDCNameHeader: "Oidc-Claim-Name",
    }

    dynamoApi := DynamoAPI(config)
    firestoreApi := FirestoreAPI(config)
    ```
