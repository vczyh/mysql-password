# MySQL Password

- Generate `authentication_string` of `mysql.user` table.
- Validate password by `authentication_string`.

Supported  authentication methods:

- [mysql_native_password](#mysql_native_password)
- [sha256_password](#sha256_password)
- [caching_sha2_password](#caching_sha2_password)

## Install

```shell
go get github.com/vczyh/mysql-password
```

## `mysql_native_password`

```go
h := NewMySQLNative()

authStr, err := h.Encrypt([]byte("password"), nil)
if err != nil {
 // handle error
}

if err := h.Validate([]byte("authStr"), []byte("password")); err != nil {
  // handle error
}
```

## `sha256_password`

```go
h := NewSHA256()

authStr, err := h.Encrypt([]byte("password"), []byte("20 bytes salt"))
if err != nil {
  // handle error
}

if err := h.Validate([]byte("authStr"), []byte("password")); err != nil {
  // handle error
}
```

## `caching_sha2_password`

```go
h := NewCachingSHA2()

authStr, err := h.Encrypt([]byte("password"), []byte("$A$005$<20 bytes salt>"))
if err != nil {
  // handle error
}

if err := h.Validate([]byte("authStr"), []byte("password")); err != nil {
  // handle error
}
```

