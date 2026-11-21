# AuthlyX Go SDK

Official Go SDK and console example for AuthlyX V3 (3.0.0 beta).

Full documentation: https://docs.authlyx.dev

## Requirements

- Windows
- Go 1.23 or newer

## Run the example

Put your app key and version in `main.go`:

```go
app, err := authlyx.NewAuthlyX(ctx, "YOUR_APP_KEY", "1.0.0")
```

Then run it:

```bat
go run .
```

You can find your app key under your app's credentials in the [dashboard](https://dash.authlyx.dev).

## Add it to your own project

Copy the `sdk` folder into your project and point your `go.mod` at it:

```go
require github.com/authlyx/sdk-go/v3 v3.0.0

replace github.com/authlyx/sdk-go/v3 => ./sdk
```

```go
import authlyx "github.com/authlyx/sdk-go/v3"

ctx := context.Background()
app, err := authlyx.NewAuthlyX(ctx, "YOUR_APP_KEY", "1.0.0")
if err != nil {
    return err
}
defer app.Close()

result, err := app.Initialize(ctx)
if err != nil {
    return err
}
if !result.Success {
    return errors.New(result.Message)
}
```

Every call returns `(Result, error)`. Check `err` first, then `Result.Success`.

## Signing in

```go
result, err := app.Login(ctx, "YOUR_USERNAME", "YOUR_PASSWORD")
result, err = app.LicenseLogin(ctx, "YOUR_LICENSE_KEY")
result, err = app.DeviceLogin(ctx)
```

Device login signs in the current Windows user without a form. The device has to be approved in your app first. See [Device login](https://docs.authlyx.dev/guides/device-login).

After signing in, the account details are in `userData`:

```go
user, err := app.UserData(ctx)
username := user["Username"]
plan := user["Plan"]
expiry := user["ExpiryDate"]
```

Every method has its own page with examples under [SDK methods](https://docs.authlyx.dev/sdks/methods/login).

## Starting up and updates

`initialize()` returns one of these codes:

| Code | Success | Meaning |
| --- | --- | --- |
| `APP_INITIALIZED` | Yes | Connected. Continue to sign-in. |
| `OFFLINE_MODE` | Yes | No internet, but this PC has saved offline access. |
| `NETWORK_...` | No | No internet and nothing saved. Offer to try again. |
| `UPDATE_REQUIRED` | No | This version is older than the one set in your dashboard. |
| `VERSION_MISMATCH` | No | This version is newer than the dashboard version and is not allowed. |

On Windows the SDK shows update messages for you: an **Update required** or **Version not supported** box when this version is refused, and an **Update available** box once after sign-in when a newer release exists. Each one shows the release notes and offers to open the download page. Set versions and download links under your app's **Updates** settings in the [dashboard](https://dash.authlyx.dev).

To show your own screen instead, turn the box off:

```go
options, err := authlyx.DefaultOptions("YOUR_APP_KEY", "1.0.0")
if err != nil {
    return err
}
options.NoUpdatePrompt = true
app, err := authlyx.New(ctx, options)
```

The failed result's `update` data then has `version`, `notes` and `url`. More in [Updates](https://docs.authlyx.dev/guides/updates) and [Allowed Versions](https://docs.authlyx.dev/guides/allowed-versions).

## Offline access

Once someone is signed in, saving offline access stores a signed permit on that PC:

```go
saved, err := app.SaveOfflineAccess(ctx)
available := app.HasOfflineAccess(ctx)
```

If they open your app later without internet, `initialize()` succeeds with the code `OFFLINE_MODE`, and they sign in with the same username and password or license key, and the SDK checks it against the saved permit. Each permit belongs to one app and one account, and signing out removes it. More in [Offline access](https://docs.authlyx.dev/guides/offline).

## Errors

`initialize()` reports a missing connection in its result. For other calls, `err` is set when AuthlyX could not be reached or something on the PC failed. When the server turns a request down, `err` is nil and `Result.Success` is false, with a `Code` and `Message` you can show to the user. All codes are listed in [Errors](https://docs.authlyx.dev/api-reference/errors).

## Coming from 2.4

V3 is a new SDK, not a drop-in update. Apps use an app key instead of the old owner ID, app name and secret, and the method names changed. Read [Move from V2 to V3](https://docs.authlyx.dev/api-reference/migration) before you switch.

## License

MIT. See `LICENSE.txt`.
