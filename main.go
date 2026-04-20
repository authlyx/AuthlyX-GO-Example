package main

import (
	"fmt"
	"os"
)

func showResult(title string, a *AuthlyX) {
	r := a.Response
	status := "FAILED"
	if r.Success {
		status = "SUCCESS"
	}
	fmt.Println()
	fmt.Printf("%s: %s\n", title, status)
	fmt.Printf("Message: %s\n", r.Message)
	if r.Code != "" {
		fmt.Printf("Code: %s\n", r.Code)
	}
	if r.StatusCode != 0 {
		fmt.Printf("Status: %d\n", r.StatusCode)
	}
}

func showUser(a *AuthlyX) {
	u := a.UserData
	fmt.Println()
	fmt.Println("USER PROFILE")
	fmt.Println("==============================================")
	fmt.Printf("Username: %s\n", orNA(u.Username))
	fmt.Printf("Email: %s\n", orNA(u.Email))
	fmt.Printf("License Key: %s\n", orNA(u.LicenseKey))
	fmt.Printf("Subscription: %s\n", orNA(u.Subscription))
	fmt.Printf("Subscription Level: %s\n", orNA(u.SubscriptionLevel))
	fmt.Printf("Expiry Date: %s\n", orNA(u.ExpiryDate))
	fmt.Printf("Days Left: %d\n", u.DaysLeft)
	fmt.Printf("Last Login: %s\n", orNA(u.LastLogin))
	fmt.Printf("Registered At: %s\n", orNA(u.RegisteredAt))
	fmt.Printf("HWID/SID: %s\n", orNA(u.Hwid))
	fmt.Printf("IP Address: %s\n", orNA(u.IpAddress))
	fmt.Println("==============================================")
}

func orNA(s string) string {
	if s == "" {
		return "N/A"
	}
	return s
}

func main() {
	api := os.Getenv("AUTHLYX_API")
	if api == "" {
		api = "https://authly.cc/api/v2"
	}

	ownerID := os.Getenv("AUTHLYX_OWNER_ID")
	if ownerID == "" {
		ownerID = "b49d11af8c42"
	}

	appName := os.Getenv("AUTHLYX_APP_NAME")
	if appName == "" {
		appName = "TEST"
	}

	version := os.Getenv("AUTHLYX_VERSION")
	if version == "" {
		version = "1.3"
	}

	secret := os.Getenv("AUTHLYX_SECRET")
	if secret == "" {
		secret = "1L0edLKqHlFv0AL3NIQ7uPpikN2ECr7aZSHrNWMo"
	}

	AuthlyXApp := NewAuthlyX(
		ownerID,
		appName,
		version,
		secret,
		true,
		api,
	)

	AuthlyXApp.Init()
	showResult("Init", AuthlyXApp)
	if !AuthlyXApp.Response.Success {
		return
	}

	username := os.Getenv("AUTHLYX_USERNAME")
	password := os.Getenv("AUTHLYX_PASSWORD")

	if username != "" && password != "" {
		AuthlyXApp.Login(username, password, "")
		showResult("Login", AuthlyXApp)
		if AuthlyXApp.Response.Success {
			showUser(AuthlyXApp)

			AuthlyXApp.SetVariable("theme", "dark")
			showResult("Set Variable", AuthlyXApp)

			val, _ := AuthlyXApp.GetVariable("theme")
			showResult("Get Variable", AuthlyXApp)
			if AuthlyXApp.Response.Success {
				fmt.Println("Value:", val)
			}

			AuthlyXApp.ValidateSession()
			showResult("Validate Session", AuthlyXApp)
		}
		return
	}

	fmt.Println()
	fmt.Println("Init completed.")
	fmt.Println("Set AUTHLYX_USERNAME and AUTHLYX_PASSWORD if you want to run the authenticated examples.")
}
