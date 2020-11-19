All providers require that a `Config` object be passed in to tell Scoutr about your environment. The configuration
accepts the following arguments:

=== "Python"

    ```python
    config = Config(
        data_table='example-data',
        auth_table='example-auth',
        groups_table='example-groups',
        audit_table='example-audit',
        primary_key='key',
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
        OIDCUsernameHeader: "Oidc-Claim-Sub",
        OIDCEmailHeader: "Oidc-Claim-Mail",
        OIDCGroupsHeader: "Oidc-Claim-Groups",
        OIDCNameHeader: []string{"Oidc-Claim-Firstname", "Oidc-Claim-Lastname"},
    }

    dynamoApi := DynamoAPI(config)
    firestoreApi := FirestoreAPI(config)
    ```
