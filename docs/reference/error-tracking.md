## Error tracking

Support for [Sentry](https://sentry.io) is built-in to Scoutr in Python. Error tracking will be added to Scoutr in Go
at a later time. Breadcrumbs are automatically added in at key points in the execution. To enable error tracking,
install the `sentry-sdk` package:

```
pip install sentry-sdk
```

And then initialize Sentry at the start of your code:

```python
import os
import sentry_sdk
from sentry_sdk.integrations.aws_lambda import AwsLambdaIntegration

sentry_sdk.init(
    dsn=os.getenv('SENTRY_DSN'),
    integrations=[AwsLambdaIntegration()],
    environment=os.getenv('ENV')
)
```

Refer to the [examples](https://github.com/GESkunkworks/scoutr/tree/master/example) to see sample usage of Sentry.
