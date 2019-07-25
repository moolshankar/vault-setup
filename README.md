# vault-setup
Hashicorp Vault Setup

Installing vault:

Using snap:
snap install vault
Add entry to .bashrc for autocomplete
complete -C /opt/softwares/vault vault

      2. Using binary download
cd /tmp/
wget https://releases.hashicorp.com/vault/1.1.2/vault_1.1.2_linux_amd64.zip
unzip vault_1.1.2_linux_amd64.zip
mkdir /opt/softwares
mv vault /opt/softwares

Create soft link for vault in /usr/bin

cd /usr/bin
ln -s /opt/softwares/vault vault

If needed add entry in ~/.bashrc for binary dir path
export PATH="$PATH:/opt/softwares"

Start vault server:

vault server -dev

Open a new tab and use vault as below:

Set Environment variable:

root@vault:~# vault status
Error checking seal status: Get https://127.0.0.1:8200/v1/sys/seal-status: http: server gave HTTP response to HTTPS client
root@vault:~# export VAULT_ADDR="http://127.0.0.1:8200"
root@vault:~# vault status
Key             Value
---             -----
Seal Type       shamir
Initialized     true
Sealed          false
Total Shares    1
Threshold       1
Version         1.1.2
Cluster Name    vault-cluster-0a5206da
Cluster ID      a133c0d5-8a39-d069-9137-d90fb4e1e3d1
HA Enabled      false
root@vault:~#


root@vault:~# export VAULT_ADDR="http://127.0.0.1:8200"

Alternatively add an entry in bashrc file :
#Hashicorp vault settings
export VAULT_ADDR="http://0.0.0.0:8200"
complete -C /opt/softwares/vault vault



root@vault:~# vault status
Key             Value
---             -----
Seal Type       shamir
Initialized     true
Sealed          false
Total Shares    1
Threshold       1
Version         1.1.2
Cluster Name    vault-cluster-6fff097e
Cluster ID      3cb519c0-376d-612d-143d-61e8cb9d8489
HA Enabled      false

Creating secret

root@vault:~# vault kv put secret/mySecret password=myPassword
Key              Value
---              -----
created_time     2019-07-15T03:40:04.436586193Z
deletion_time    n/a
destroyed        false
version          1

Getting secret

root@vault:~# vault kv get secret/mySecret
====== Metadata ======
Key              Value
---              -----
created_time     2019-07-15T03:40:04.436586193Z
deletion_time    n/a
destroyed        false
version          1

====== Data ======
Key         Value
---         -----
password    myPassword

Getting secret in JSON format

root@vault:~# vault kv get -format=json secret/mySecret
{
  "request_id": "6dc2cc88-ed77-8966-ef90-880596c5ea8c",
  "lease_id": "",
  "lease_duration": 0,
  "renewable": false,
  "data": {
    "data": {
      "password": "myPassword"
    },
    "metadata": {
      "created_time": "2019-07-15T03:40:04.436586193Z",
      "deletion_time": "",
      "destroyed": false,
      "version": 1
    }
  },
  "warnings": null
}

Secret Engines Paths:

Secret (secret/mySecret/dbPassword)
mySecret
password=myPassword
Ssh (ssh/roles/admin)
Role
admin
Ssh (ssh/roles/admin)
config
Mysqldb

List secrets

root@vault:~# vault secrets list 
Path          Type         Accessor              Description
----          ----         --------              -----------
cubbyhole/    cubbyhole    cubbyhole_25a41526    per-token private secret storage
identity/     identity     identity_2bb5c159     identity store
secret/       kv           kv_15fefb76           key/value secret storage
sys/          system       system_3f197531       system endpoints used for control, policy and debugging
root@vault:~# 


Cubbyhole : One secret per token storage
Identitiy : Indentity of secrets stored in vault
Secret : Generic secret kv storage
Sys : Vault admin management like role policies, generating new root key, unsealing vault


Adding a new secret engine (enabling new secret path)

root@vault:~#  vault secrets enable -path=myApp kv
Success! Enabled the kv secrets engine at: myApp/
root@vault:~# vault secrets list 
Path          Type         Accessor              Description
----          ----         --------              -----------
cubbyhole/    cubbyhole    cubbyhole_25a41526    per-token private secret storage
identity/     identity     identity_2bb5c159     identity store
myApp/        kv           kv_474f5346           n/a
secret/       kv           kv_15fefb76           key/value secret storage
sys/          system       system_3f197531       system endpoints used for control, policy and debugging
root@vault:~# 

root@vault:~# vault kv put myApp/myOtherSecret key=value 
Success! Data written to: myApp/myOtherSecret
root@vault:~# vault kv get myApp/myOtherSecret 
=== Data ===
Key    Value
---    -----
key    value

Path-help

root@vault:~# vault path-help secret
## DESCRIPTION

This backend provides a versioned key-value store. The kv backend reads and
writes arbitrary secrets to the storage backend. The secrets are
encrypted/decrypted by Vault: they are never stored unencrypted in the backend
and the backend never has an opportunity to see the unencrypted value. Each key
can have a configured number of versions, and versions can be retrieved based on
their version numbers.

## PATHS

The following paths are supported by this backend. To view help for
any of the paths below, use the help command with any route matching
the path pattern. Note that depending on the policy of your auth token,
you may or may not be able to access certain paths.

    ^.*$


    ^config$
        Configures settings for the KV store

    ^data/(?P<path>.*)$
        Write, Read, and Delete data in the Key-Value Store.

    ^delete/(?P<path>.*)$
        Marks one or more versions as deleted in the KV store.

    ^destroy/(?P<path>.*)$
        Permanently removes one or more versions in the KV store

    ^metadata/(?P<path>.*)$
        Configures settings for the KV store

    ^undelete/(?P<path>.*)$
        Undeletes one or more versions from the KV store.


Note: path-help commands displays detailed information about the list of path supported by secrets engines.
Enabling new secret

root@vault:~# vault secrets enable database 
Success! Enabled the database secrets engine at: database/


root@vault:~# vault path-help database
## DESCRIPTION

The database backend supports using many different databases
as secret backends, including but not limited to:
cassandra, mssql, mysql, postgres

After mounting this backend, configure it using the endpoints within
the "database/config/" path.

## PATHS

The following paths are supported by this backend. To view help for
any of the paths below, use the help command with any route matching
the path pattern. Note that depending on the policy of your auth token,
you may or may not be able to access certain paths.

    ^config/(?P<name>\w(([\w-.]+)?\w)?)$
        Configure connection details to a database plugin.

    ^config/?$
        Configure connection details to a database plugin.

    ^creds/(?P<name>\w(([\w-.]+)?\w)?)$
        Request database credentials for a certain role.

    ^reset/(?P<name>\w(([\w-.]+)?\w)?)$
        Resets a database plugin.

    ^roles/(?P<name>\w(([\w-.]+)?\w)?)$
        Manage the roles that can be created with this backend.

    ^roles/?$
        Manage the roles that can be created with this backend.

    ^rotate-root/(?P<name>\w(([\w-.]+)?\w)?)$
        Request database credentials for a certain role.

Lets look one step deeper

root@vault:~# vault path-help database/roles
Request:        roles
Matching Route: ^roles/?$

Manage the roles that can be created with this backend.


## DESCRIPTION

This path lets you manage the roles that can be created with this backend.

The "db_name" parameter is required and configures the name of the database
connection to use.

The "creation_statements" parameter customizes the string used to create the
credentials. This can be a sequence of SQL queries, or other statement formats
for a particular database type. Some substitution will be done to the statement
strings for certain keys. The names of the variables must be surrounded by "{{"
and "}}" to be replaced.

  * "name" - The random username generated for the DB user.

  * "password" - The random password generated for the DB user.

  * "expiration" - The timestamp when this user will expire.

Example of a decent creation_statements for a postgresql database plugin:

	CREATE ROLE "{{name}}" WITH
	  LOGIN
	  PASSWORD '{{password}}'
	  VALID UNTIL '{{expiration}}';
	GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO "{{name}}";

The "revocation_statements" parameter customizes the statement string used to
revoke a user. Example of a decent revocation_statements for a postgresql
database plugin:

	REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM {{name}};
	REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM {{name}};
	REVOKE USAGE ON SCHEMA public FROM {{name}};
	DROP ROLE IF EXISTS {{name}};

The "renew_statements" parameter customizes the statement string used to renew a
user.
The "rollback_statements' parameter customizes the statement string used to
rollback a change if needed.


Learn more on vault documentation online


Vault credential authentication


Human authentication: Userpass, AD/LDAP, Cloud (AWS, Azure, Google Cloud Platform), Github

Non human authentication:
Approle : Used by applications and automation tools to authenticate with vault (Using approle)
Kubernetes : Kubernetes service account token

Note: Each of these has a path involved and must be enabled individually.

Creating user pass authentication

root@vault:~# vault auth list
Path      Type     Accessor               Description
----      ----     --------               -----------
token/    token    auth_token_64d27f6b    token based credentials

Enable userpass

root@vault:~# vault auth enable userpass 
Success! Enabled userpass auth method at: userpass/

Create new userpass

root@vault:~# vault write auth/userpass/users/vaultuser password=vault
Success! Data written to: auth/userpass/users/vaultuser

Login using created userpass
root@vault:~# vault login -method=userpass username=vaultuser password=vault
Success! You are now authenticated. The token information displayed below
is already stored in the token helper. You do NOT need to run "vault login"
again. Future Vault requests will automatically use this token.

Key                    Value
---                    -----
token                  s.lJ3zJ957vaZhSDNK2jVNbiE4
token_accessor         tFVBpBhJGKE9EHUdwKGIbkUH
token_duration         768h
token_renewable        true
token_policies         ["default"]
identity_policies      []
policies               ["default"]
token_meta_username    vaultuser

Logging in to vault using user token

root@vault:~# vault login s.lJ3zJ957vaZhSDNK2jVNbiE4
Success! You are now authenticated. The token information displayed below
is already stored in the token helper. You do NOT need to run "vault login"
again. Future Vault requests will automatically use this token.

Key                    Value
---                    -----
token                  s.lJ3zJ957vaZhSDNK2jVNbiE4
token_accessor         tFVBpBhJGKE9EHUdwKGIbkUH
token_duration         767h55m57s
token_renewable        true
token_policies         ["default"]
identity_policies      []
policies               ["default"]
token_meta_username    vaultuser
root@vault:~# 

Note: user token has a specific token_duration as per specified policy while root token has infinite token_duration.

root@vault:~# vault login s.JRIsQ9HiUmlHJ5r2QH1UiLic
Success! You are now authenticated. The token information displayed below
is already stored in the token helper. You do NOT need to run "vault login"
again. Future Vault requests will automatically use this token.

Key                  Value
---                  -----
token                s.JRIsQ9HiUmlHJ5r2QH1UiLic
token_accessor       EVeVteSfBCOw0G35GumTa48h
token_duration       ∞
token_renewable      false
token_policies       ["root"]
identity_policies    []
policies             ["root"]
root@vault:~# 


Once logged in with a token we can create a new token with same policies as logged in token

root@vault:~# vault token create
Key                  Value
---                  -----
token                s.r3zQiRWWxPQdsax2b9vnmkSM
token_accessor       uqcfvAv4GqQKbxRZyslcW632
token_duration       ∞
token_renewable      false
token_policies       ["root"]
identity_policies    []
policies             ["root"]

Note: The new token is the child of logged in token, so once parent token is revoked or expires all child will also expires.

Listing the accessors

root@vault:~# vault list auth/token/accessors
Keys
----
EVeVteSfBCOw0G35GumTa48h
tFVBpBhJGKE9EHUdwKGIbkUH
uqcfvAv4GqQKbxRZyslcW632

Assessors can be used to manage token without actually having the token. Like lookup, revoke

root@vault:~# vault token lookup -accessor EVeVteSfBCOw0G35GumTa48h
Key                 Value
---                 -----
accessor            EVeVteSfBCOw0G35GumTa48h
creation_time       1563243714
creation_ttl        0s
display_name        root
entity_id           n/a
expire_time         <nil>
explicit_max_ttl    0s
id                  n/a
meta                <nil>
num_uses            0
orphan              true
path                auth/token/root
policies            [root]
ttl                 0s
type                service
root@vault:~# vault token revoke -accessor EVeVteSfBCOw0G35GumTa48h
Success! Revoked token (if it existed)


Create TTL for token

root@vault:~# vault token create --ttl=5m
Key                  Value
---                  -----
token                s.qrCQzqpNuDMqPIz3Dz17Kr3V
token_accessor       qb1GXhrcSJCnG46V0QorrlvW
token_duration       5m
token_renewable      true
token_policies       ["root"]
identity_policies    []
policies             ["root"]


Policies

Policies are associated with paths and are used to generate token with specific capabilities.
Policies are defined in HCL (Hashicorp configuration Language) JSON compatible format. 

Defined capabilities on a path:
create (POST/PUT)
read (GET)
update (POST/PUT)
delete (DELETE)
list (LIST)
sudo
Deny

A token can be generated with multiple policies.

Built in Policies
Root
Default

Note: The only exception is that a root token cannot read a secret stored in cubbyhole.

Example:

app-policy.hcl

path “secret/dev” {
	capabilities = [“read”]
}

dev-policy.hcl

path “secret/dev” {
	capabilities = [“create”,”update”,“read”,”list”]
}

Creating policies in vault

root@vault:~# vault policy list 
default
root
root@vault:~# vault policy read default 
# Allow tokens to look up their own properties
path "auth/token/lookup-self" {
    capabilities = ["read"]
}

# Allow tokens to renew themselves
path "auth/token/renew-self" {
    capabilities = ["update"]
}

# Allow tokens to revoke themselves
path "auth/token/revoke-self" {
    capabilities = ["update"]
}

# Allow a token to look up its own capabilities on a path
path "sys/capabilities-self" {
    capabilities = ["update"]
}

# Allow a token to look up its own entity by id or name
path "identity/entity/id/{{identity.entity.id}}" {
  capabilities = ["read"]
}
path "identity/entity/name/{{identity.entity.name}}" {
  capabilities = ["read"]
}


# Allow a token to look up its resultant ACL from all policies. This is useful
# for UIs. It is an internal path because the format may change at any time
# based on how the internal ACL features and capabilities change.
path "sys/internal/ui/resultant-acl" {
    capabilities = ["read"]
}

# Allow a token to renew a lease via lease_id in the request body; old path for
# old clients, new path for newer
path "sys/renew" {
    capabilities = ["update"]
}
path "sys/leases/renew" {
    capabilities = ["update"]
}

# Allow looking up lease properties. This requires knowing the lease ID ahead
# of time and does not divulge any sensitive information.
path "sys/leases/lookup" {
    capabilities = ["update"]
}

# Allow a token to manage its own cubbyhole
path "cubbyhole/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
}

# Allow a token to wrap arbitrary values in a response-wrapping token
path "sys/wrapping/wrap" {
    capabilities = ["update"]
}

# Allow a token to look up the creation time and TTL of a given
# response-wrapping token
path "sys/wrapping/lookup" {
    capabilities = ["update"]
}

# Allow a token to unwrap a response-wrapping token. This is a convenience to
# avoid client token swapping since this is also part of the response wrapping
# policy.
path "sys/wrapping/unwrap" {
    capabilities = ["update"]
}

# Allow general purpose tools
path "sys/tools/hash" {
    capabilities = ["update"]
}
path "sys/tools/hash/*" {
    capabilities = ["update"]
}
path "sys/tools/random" {
    capabilities = ["update"]
}
path "sys/tools/random/*" {
    capabilities = ["update"]
}

# Allow checking the status of a Control Group request if the user has the
# accessor
path "sys/control-group/request" {
    capabilities = ["update"]
}
root@vault:~# vault policy write dev-policy dev-policy.hcl
root@vault:~# vault policy write app-policy app-policy.hcl


Applying policy to user (userpass)

root@vault:~# vault auth enable userpass
root@vault:~# vault write auth/userpass/users/app password=app policies=app-policy

Checking token capabilities on a secret 

root@vault:~# vault token capabilities secret/data/dev/
create, list, read, update


Production mode server

Set configuration
Start and Initialize
Unseal
Test using cli command


Configuration

disable_mlock = true

storage “file” {
	“path” = “vault/file”
}

listener “tcp”{
	address = “0.0.0.0:8200”
	tls_disable = 1
}

Start server

vault server -config=config.hcl 
==> Vault server configuration:

                     Cgo: disabled
              Listener 1: tcp (addr: "0.0.0.0:8200", cluster address: "0.0.0.0:8201", max_request_duration: "1m30s", max_request_size: "33554432", tls: "disabled")
               Log Level: info
                   Mlock: supported: true, enabled: false
                 Storage: file
                 Version: Vault v1.1.2
             Version Sha: 0082501623c0b704b87b1fbc84c2d725994bac54

==> Vault server started! Log data will stream in below:

2019-07-18T03:51:26.527Z [WARN]  no `api_addr` value specified in config or in VAULT_API_ADDR; falling back to detection if possible, but this value should be manually set

 Initialize vault:

root@vault:~# vault operator init
Unseal Key 1: pFml23ZuQM7bYOVY50fJeM7LvszvJ/l3/IViPHCxJgne
Unseal Key 2: gOicldBpUkH9TXMyj4IyRsTAgRDDH9wSusEChyOFFwwb
Unseal Key 3: O63T8QOWW9KzNZvi1l/Q51BateA/WYbw7bbcsvASgVh3
Unseal Key 4: JqqeRI3Ctb2Euf88qjtNZDrgRwJYmEg7gKMHvxdCzIG3
Unseal Key 5: 49iEQFz2RzqZPYGa2I+94/SXbjjbbh1R/DG1VAtPUyhv

Initial Root Token: s.hBQ6pCZvz4EjX3F3ymcxNrvk

Vault initialized with 5 key shares and a key threshold of 3. Please securely
distribute the key shares printed above. When the Vault is re-sealed,
restarted, or stopped, you must supply at least 3 of these keys to unseal it
before it can start servicing requests.

Vault does not store the generated master key. Without at least 3 key to
reconstruct the master key, Vault will remain permanently sealed!

It is possible to generate new unseal keys, provided you have a quorum of
existing unseal keys shares. See "vault operator rekey" for more information.

Try to login using root token

root@vault:~# vault login s.hBQ6pCZvz4EjX3F3ymcxNrvk
Error authenticating: error looking up token: Error making API request.

URL: GET http://0.0.0.0:8200/v1/auth/token/lookup-self
Code: 503. Errors:

* error performing token check: Vault is sealed

Cannot login since vault is sealed, lets try to unseal vault using key shards provided while init (one by one)


root@vault:~# vault operator unseal pFml23ZuQM7bYOVY50fJeM7LvszvJ/l3/IViPHCxJgne
Key                Value
---                -----
Seal Type          shamir
Initialized        true
Sealed             true
Total Shares       5
Threshold          3
Unseal Progress    1/3
Unseal Nonce       1b526495-d223-7629-f142-fb8ae41e9ea6
Version            1.1.2
HA Enabled         false

root@vault:~# vault operator unseal gOicldBpUkH9TXMyj4IyRsTAgRDDH9wSusEChyOFFwwb
Key                Value
---                -----
Seal Type          shamir
Initialized        true
Sealed             true
Total Shares       5
Threshold          3
Unseal Progress    2/3
Unseal Nonce       1b526495-d223-7629-f142-fb8ae41e9ea6
Version            1.1.2
HA Enabled         false
root@vault:~# vault operator unseal O63T8QOWW9KzNZvi1l/Q51BateA/WYbw7bbcsvASgVh3
Key             Value
---             -----
Seal Type       shamir
Initialized     true
Sealed          false
Total Shares    5
Threshold       3
Version         1.1.2
Cluster Name    vault-cluster-f9058be5
Cluster ID      174efdee-59fa-eca3-6208-c1aaf4220ed3
HA Enabled      false
root@vault:~#


Lets try to login one more time with unsealed Vault

root@vault:~# vault login s.hBQ6pCZvz4EjX3F3ymcxNrvk
Success! You are now authenticated. The token information displayed below
is already stored in the token helper. You do NOT need to run "vault login"
again. Future Vault requests will automatically use this token.

Key                  Value
---                  -----
token                s.hBQ6pCZvz4EjX3F3ymcxNrvk
token_accessor       pO5u6T1z96EIKJ8X4ZVsDkZ8
token_duration       ∞
token_renewable      false
token_policies       ["root"]
identity_policies    []
policies             ["root"]

Vault is unsealed and we are successfully logged in

Create docker-compose.yml to install and up below services:

Vaultserver, mariadb, jenkins, ssh

SSH secret engine

Integrates vault with SSH server
Key signing
One time password

SSH OTP setup





Directory structure


