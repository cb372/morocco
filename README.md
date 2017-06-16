# Morocco

Store your secrets securely in the cloud.

Morocco is a command-line secrets store supporting AWS (implemented) and Google Cloud Platform (coming soon).

## How to install

Download the latest binary from the [releases page](https://github.com/cb372/morocco/releases). There are binaries for Mac and Linux.

(Optional) put the binary somewhere on your `$PATH`.

## How to use

### Initial setup

Before you can start storing secrets, you will need to run `morocco aws setup`.

This will create a DynamoDB table and a KMS (Key Management Service) customer master key.

```
$ morocco aws setup
Set up complete. Created Dynamo table. Created customer master key.
```

### Storing a secret

Use the "put" command to store a secret:

```
$ morocco aws put db.password so-very-secret
Stored secret.
```

Here `db.password` is an identifier for the secret, and `so-very-secret` is the value you want to store securely.

If a secret with that ID already exists and you want to update it, use the `--overwrite` option:

```
$ morocco aws put --overwrite db.password new-value
Stored secret.
```

### Getting a secret

```
$ morocco aws get db.password
new-value
```

### Listing secrets

```
$ morocco aws list
db.password
other.secret
```

### Deleting a secret

```
$ morocco aws delete db.password
Deleted secret.
```

## Encryption

Secrets are encrypted using AES-256 in CBC (Cipher Block Chaining) mode with PKCS padding. IVs are secure random bytes.

## Mole

Morocco Mole is the sidekick of Secret Squirrel, who knows a thing or two about security.

## Acknowledgements

Morocco was inspired by [credstash](https://github.com/fugue/credstash).
