# AuthlyX Go SDK

This is a Go authentication SDK for desktop and CLI applications that want simple integration with the AuthlyX API.

This folder includes the SDK in `authlyx.go` and a runnable example in `main.go`.

## Requirements

- Go `1.21` or later

## Quick Start

```go
package main

func main() {
    AuthlyXApp := NewAuthlyX(
        "12345678",
        "MYAPP",
        "1.0.0",
        "your-secret",
        true,
        "https://authly.cc/api/v2",
    )

    AuthlyXApp.Init()
}
```

## Optional Parameters

```go
AuthlyXApp := NewAuthlyX(
    "12345678",
    "MYAPP",
    "1.0.0",
    "your-secret",
    false,
    "https://example.com/api/v2",
)
```

### Available options

- `debug`
  - Default: `true`
  - Set `false` to disable SDK logs

- `api`
  - Default: `https://authly.cc/api/v2`
  - Use this for your custom domain

## Available Methods

- `Init()`
- `Login(identifier, password, deviceType)`
- `Register(username, password, licenseKey, email)`
- `ChangePassword(oldPassword, newPassword)`
- `ExtendTime(username, licenseKey)`
- `GetVariable(key)`
- `SetVariable(key, value)`
- `Log(message)`
- `GetChats(channelName, limit, cursor)`
- `SendChat(message, channelName)`
- `ValidateSession()`

## Authentication Example

```go
// Username + password
AuthlyXApp.Login("username", "password", "")

// License key only
AuthlyXApp.Login("XXXXX-XXXXX-XXXXX-XXXXX-XXXXX", "", "")

// Device login
AuthlyXApp.Login("YOUR_MOTHERBOARD_ID", "", "motherboard")
```

## Username Login Example

```go
AuthlyXApp.Login("username", "password", "")

if AuthlyXApp.Response.Success {
    println("Login success")
    println(AuthlyXApp.UserData.Username)
    println(AuthlyXApp.UserData.SubscriptionLevel)
} else {
    println(AuthlyXApp.Response.Message)
}
```

## Variable Example

```go
AuthlyXApp.SetVariable("theme", "dark")

value, _ := AuthlyXApp.GetVariable("theme")
println(value)
```

## Logging

By default, SDK logging is enabled.

Logs are written to:

`C:\ProgramData\AuthlyX\{AppName}\YYYY_MM_DD.log`

To disable logs:

```go
AuthlyXApp := NewAuthlyX(
    "12345678",
    "MYAPP",
    "1.0.0",
    "your-secret",
    false,
    "https://authly.cc/api/v2",
)
```

Sensitive values such as passwords, secrets, session IDs, request IDs, nonces, license keys, and hashes are masked automatically.

## Example Project

The runnable example in `main.go` uses the public test app by default for `Init()`.

If you want to run the authenticated example too, set:

- `AUTHLYX_USERNAME`
- `AUTHLYX_PASSWORD`

Then run:

```powershell
go run .
```
