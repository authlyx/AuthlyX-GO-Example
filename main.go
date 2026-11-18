package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"

	authlyx "github.com/authlyx/sdk-go/v3"
)

var (
	input       = bufio.NewReader(os.Stdin)
	interactive = isTerminal(os.Stdin) && isTerminal(os.Stdout)
)

func isTerminal(file *os.File) bool {
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func clear() {
	if !interactive {
		return
	}
	if runtime.GOOS == "windows" {
		command := exec.Command("cmd", "/c", "cls")
		command.Stdout = os.Stdout
		_ = command.Run()
	} else {
		fmt.Print("\x1b[2J\x1b[H")
	}
}

func title(text string) {
	clear()
	fmt.Print("AuthlyX  |  Go example\n\n" + text + "\n\n")
}

func ask(label string) string {
	fmt.Print(label + ": ")
	line, err := input.ReadString('\n')
	if err != nil && line == "" {
		os.Exit(0)
	}
	return strings.TrimSpace(line)
}

func pause() { ask("\nPress Enter to go back") }

func message(err error) string {
	var failure *authlyx.Error
	if errors.As(err, &failure) {
		return failure.Message
	}
	return err.Error()
}

func text(value any) string {
	switch v := value.(type) {
	case nil:
		return "-"
	case string:
		if v == "" {
			return "-"
		}
		return v
	case bool:
		if v {
			return "Yes"
		}
		return "No"
	case float64:
		return fmt.Sprintf("%g", v)
	default:
		return fmt.Sprint(v)
	}
}

func when(value any) string {
	if s, ok := value.(string); ok && len(s) >= 16 {
		return s[:10] + " " + s[11:16] + " UTC"
	}
	return text(value)
}

func expiry(user map[string]any) string {
	if s, ok := user["expiry"].(string); ok && len(s) >= 10 {
		return s[:10]
	}
	return "Never"
}

func row(label, value string) { fmt.Printf("  %-16s%s\n", label, value) }

func showAccount(user map[string]any) {
	title("Account details")
	switch user["type"] {
	case "license":
		row("License key", text(user["name"]))
	case "device":
		row("Device", text(user["name"]))
	default:
		row("Username", text(user["name"]))
		if key, ok := user["licenseKey"].(string); ok && key != "" {
			row("License key", key)
		}
	}
	row("Email", text(user["email"]))
	row("Plan", text(user["plan"]))
	row("Expires", expiry(user))
	if limit, ok := user["deviceLimit"].(float64); ok && limit == 0 {
		row("Device limit", "Unlimited")
	} else {
		row("Device limit", text(user["deviceLimit"]))
	}
	row("Registered", when(user["registeredAt"]))
	row("Last sign-in", when(user["lastLogin"]))
	row("System ID", text(user["systemId"]))
	row("IP address", text(user["ipAddress"]))
	row("Country", text(user["country"]))
}

func showList(heading string, value any, empty string) {
	fmt.Println(heading)
	values, _ := value.(map[string]any)
	if len(values) == 0 {
		fmt.Println("  " + empty)
		return
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		row(key, text(values[key]))
	}
}

func signIn(ctx context.Context, app *authlyx.AuthlyX, notice string) (string, bool) {
	title("Sign in")
	if notice != "" {
		fmt.Print(notice + "\n\n")
	}
	fmt.Print("  1  Username and password\n  2  License key\n  3  This device\n  0  Exit\n\n")
	var err error
	switch ask("Choose") {
	case "1":
		username := ask("Username")
		_, err = app.Login(ctx, username, ask("Password"))
	case "2":
		_, err = app.LicenseLogin(ctx, ask("License key"))
	case "3":
		_, err = app.DeviceLogin(ctx)
	case "0", "":
		return "", false
	default:
		return "Choose 1, 2, 3 or 0.", true
	}
	if err != nil {
		return message(err), true
	}
	return "", true
}

func mainMenu(ctx context.Context, app *authlyx.AuthlyX, notice string) (string, bool) {
	user, err := app.UserData(ctx)
	if err != nil {
		return message(err), true
	}
	title("Signed in as " + text(user["name"]) + "  |  " + text(user["plan"]) + " plan  |  Expires " + expiry(user))
	if notice != "" {
		fmt.Print(notice + "\n\n")
	}
	fmt.Print("  1  Account details          6  Check session\n" +
		"  2  Read a variable          7  Send a log\n" +
		"  3  Update a variable        8  Save offline access\n" +
		"  4  Features and metadata    9  Sign out\n" +
		"  5  Fetch a script           0  Exit\n\n")
	var result authlyx.Result
	switch ask("Choose") {
	case "0", "":
		return "", false
	case "1":
		showAccount(user)
	case "2":
		name := ask("Variable name")
		result, err = app.GetVariable(ctx, name)
		title("Variable")
		if err == nil {
			row("Name", name)
			row("Value", text(result.Data["value"]))
		}
	case "3":
		name, value := ask("Variable name"), ask("New value")
		result, err = app.UpdateVariable(ctx, name, value)
		title("Update a variable")
		if err == nil {
			fmt.Println(result.Message)
		}
	case "4":
		features, featureErr := app.GetFeatures(ctx)
		metadata, metadataErr := app.GetAllMetadata(ctx)
		title("Features and metadata")
		if err = errors.Join(featureErr, metadataErr); err == nil {
			showList("Features", features.Data["features"], "No features on this plan.")
			fmt.Println()
			showList("Metadata", metadata.Data["metadata"], "No metadata.")
		}
	case "5":
		name := ask("Script name")
		result, err = app.GetScript(ctx, name, 0)
		title("Script: " + name)
		if err == nil {
			fmt.Println(text(result.Data["content"]))
		}
	case "6":
		result, err = app.CheckSession(ctx)
		title("Session")
		if err == nil {
			fmt.Println(result.Message)
		}
	case "7":
		result, err = app.Log(ctx, ask("Log message"))
		title("Send a log")
		if err == nil {
			fmt.Println(result.Message)
		}
	case "8":
		result, err = app.SaveOfflineAccess(ctx)
		title("Offline access")
		if err == nil {
			fmt.Println(result.Message)
		}
	case "9":
		if err = app.Logout(ctx); err != nil {
			return message(err), true
		}
		return "You are signed out.", true
	default:
		return "Choose one of the listed options.", true
	}
	if err != nil {
		fmt.Println(message(err))
	}
	pause()
	return "", true
}

func main() {
	ctx := context.Background()
	title("Connecting...")
	app, err := authlyx.NewAuthlyX(ctx, "test_09f6d82a741beb5078fbb11b49c178b3e03ec556a5d130fc", "1.0")
	if err != nil {
		fmt.Println(message(err))
		os.Exit(1)
	}
	defer app.Close()
	notice, running := "", true
	for {
		title("Connecting...")
		initialized, err := app.Initialize(ctx)
		if err == nil && initialized.Success {
			if initialized.Code == "OFFLINE_MODE" {
				notice = initialized.Message
			}
			break
		}
		title("Could not connect")
		if err != nil {
			fmt.Println(message(err))
		} else {
			fmt.Println(initialized.Message)
		}
		fmt.Print("\n  1  Try again\n  0  Exit\n\n")
		if ask("Choose") != "1" {
			return
		}
	}
	for running {
		if app.HasAccess(ctx) {
			notice, running = mainMenu(ctx, app, notice)
		} else {
			notice, running = signIn(ctx, app, notice)
		}
	}
}
