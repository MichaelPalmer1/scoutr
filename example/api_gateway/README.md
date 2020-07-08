# Example API

This is an example implemention of an API that uses Scoutr with a DynamoDB backend

# Deployment
Setup the `provider` section of `serverless.yml` with the `profile: <youraccountprofile>` and then run:

```
make deploy
```

A deployment docker will be built and it will add the contents of this example directory and deploy it to your account. 

# Notes
If you want to take this example and modify it make sure to change the names in the following locations:

* change `example` folder to be your package name.
* search and replace all references to `example.` with `<yourpackagename>.`
* if in your DataTable you put a primary key other than `id` then make sure to update the code in `get.py` etc., with the new primary key. 
