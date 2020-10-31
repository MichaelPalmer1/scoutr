class Config:
    data_table: str
    auth_table: str
    group_table: str
    audit_table: str = ''
    primary_key: str = 'id'
    log_retention_days: int = 30
    oidc_username_header: str = ''
    oidc_name_header: str = ''
    oidc_email_header: str = ''
    oidc_group_header: str = ''

    def __init__(self, data_table: str, auth_table: str, group_table: str, audit_table: str = '',
                 primary_key: str = 'id', log_retention_days: int = 30, oidc_username_header: str = '',
                 oidc_name_header: str = '', oidc_email_header: str = '', oidc_group_header: str = ''):
        self.data_table = data_table
        self.auth_table = auth_table
        self.audit_table = audit_table
        self.group_table = group_table
        self.primary_key = primary_key
        self.log_retention_days = log_retention_days
        self.oidc_username_header = oidc_username_header
        self.oidc_name_header = oidc_name_header
        self.oidc_email_header = oidc_email_header
        self.oidc_group_header = oidc_group_header


class MongoConfig(Config):
    connection_string: str
    database: str

    def __init__(self, connection_string: str, database: str, data_table: str, auth_table: str, group_table: str,
                 audit_table: str = '', primary_key: str = 'id', log_retention_days: int = 30,
                 oidc_username_header: str = '', oidc_name_header: str = '',
                 oidc_email_header: str = '', oidc_group_header: str = ''):
        super(MongoConfig, self).__init__(
            data_table=data_table,
            auth_table=auth_table,
            group_table=group_table,
            audit_table=audit_table,
            primary_key=primary_key,
            log_retention_days=log_retention_days,
            oidc_username_header=oidc_username_header,
            oidc_name_header=oidc_name_header,
            oidc_email_header=oidc_email_header,
            oidc_group_header=oidc_group_header
        )
        self.connection_string = connection_string
        self.database = database
