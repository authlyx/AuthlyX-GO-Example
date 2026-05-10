// AuthlyX SDK Version 2.1
package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/csv"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

type Response struct {
	Success      bool
	Message      string
	Raw          string
	Code         string
	StatusCode   int
	RequestID    string
	Nonce        string
	SignatureKID string
}

type UserData struct {
	Username          string
	Email             string
	LicenseKey        string
	Subscription      string
	SubscriptionLevel string
	ExpiryDate        string
	DaysLeft          int
	LastLogin         string
	Hwid              string
	IpAddress         string
	RegisteredAt      string
}

type VariableData struct {
	VarKey    string
	VarValue  string
	UpdatedAt string
}

type UpdateData struct {
	Available         bool
	LatestVersion     string
	DownloadUrl       string
	AutoUpdateEnabled bool
	ForceUpdate       bool
	Changelog         string
	ShowReminder      bool
	ReminderMessage   string
	AllowedUntil      string
}

type ChatMessage struct {
	ID        any
	Username  string
	Message   string
	CreatedAt string
}

type ChatMessages struct {
	ChannelName string
	Messages    []ChatMessage
	Count       int
	NextCursor  string
	HasMore     bool
}

type AuthlyX struct {
	OwnerID string
	AppName string
	Version string
	Secret  string
	BaseURL string
	Debug   bool
	ServerPublicKeyDerBase64 string
	RequireSignedResponses  bool

	SessionID       string
	ApplicationHash string
	Initialized     bool
	CachedPublicIP  string
	CachedIPExpires time.Time

	Response     Response
	UserData     UserData
	VariableData VariableData
	UpdateData   UpdateData
	ChatMessages ChatMessages

	httpClient *http.Client
}

func NewAuthlyX(ownerID, appName, version, secret string, debug bool, api string) *AuthlyX {
	base := strings.TrimRight(strings.TrimSpace(api), "/")
	if base == "" {
		base = "https://authly.cc/api/v2"
	}

	a := &AuthlyX{
		OwnerID:    ownerID,
		AppName:    appName,
		Version:    version,
		Secret:     secret,
		BaseURL:    base,
		Debug:      debug,
		ServerPublicKeyDerBase64: "MCowBQYDK2VwAyEAgX5lXPhkadeQozyudzTxDXopdJxYexD5qZ0yEq9UOMU=",
		RequireSignedResponses:  false,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
	a.ApplicationHash = a.GetCurrentApplicationHash()
	a.log("[SDK] AuthlyX initialized for app '" + a.AppName + "' using '" + a.BaseURL + "'.")
	return a
}

func (a *AuthlyX) resetResponse() {
	a.Response = Response{}
}

func (a *AuthlyX) setFailure(code, message, raw string, statusCode int) bool {
	a.Response.Success = false
	a.Response.Code = code
	a.Response.Message = message
	a.Response.Raw = raw
	a.Response.StatusCode = statusCode
	return false
}

func (a *AuthlyX) ensureInitialized() bool {
	if a.Initialized && a.SessionID != "" {
		return true
	}
	return a.setFailure("NOT_INITIALIZED", "AuthlyX is not initialized. Call Init() first.", "", 0)
}

func (a *AuthlyX) log(content string) {
	if !a.Debug || strings.TrimSpace(content) == "" {
		return
	}
	defer func() { _ = recover() }()

	root := ""
	if runtime.GOOS == "windows" {
		pd := os.Getenv("PROGRAMDATA")
		if pd != "" {
			root = filepath.Join(pd, "AuthlyX", safeDir(a.AppName))
		}
	}
	if root == "" {
		home, _ := os.UserHomeDir()
		root = filepath.Join(home, ".authlyx", safeDir(a.AppName))
	}

	_ = os.MkdirAll(root, 0755)
	logPath := filepath.Join(root, time.Now().UTC().Format("2006_01_02")+".log")
	line := "[" + time.Now().UTC().Format("15:04:05") + "] " + maskSensitive(content) + "\n"
	_ = os.WriteFile(logPath, appendBytes(readFileBytes(logPath), []byte(line)), 0644)
}

func safeDir(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "default"
	}
	re := regexp.MustCompile(`[^a-zA-Z0-9._-]+`)
	return re.ReplaceAllString(s, "_")
}

func readFileBytes(p string) []byte {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	return b
}

func appendBytes(a, b []byte) []byte {
	if len(a) == 0 {
		return b
	}
	out := make([]byte, 0, len(a)+len(b))
	out = append(out, a...)
	out = append(out, b...)
	return out
}

func maskSensitive(s string) string {
	if s == "" {
		return s
	}
	pats := []*regexp.Regexp{
		regexp.MustCompile(`(?i)"session_id"\s*:\s*"[^"]*"`),
		regexp.MustCompile(`(?i)"owner_id"\s*:\s*"[^"]*"`),
		regexp.MustCompile(`(?i)"secret"\s*:\s*"[^"]*"`),
		regexp.MustCompile(`(?i)"password"\s*:\s*"[^"]*"`),
		regexp.MustCompile(`(?i)"key"\s*:\s*"[^"]*"`),
		regexp.MustCompile(`(?i)"license_key"\s*:\s*"[^"]*"`),
		regexp.MustCompile(`(?i)"hash"\s*:\s*"[^"]*"`),
		regexp.MustCompile(`(?i)"request_id"\s*:\s*"[^"]*"`),
		regexp.MustCompile(`(?i)"nonce"\s*:\s*"[^"]*"`),
		regexp.MustCompile(`(?i)"hwid"\s*:\s*"[^"]*"`),
		regexp.MustCompile(`(?i)"sid"\s*:\s*"[^"]*"`),
	}
	out := s
	for _, p := range pats {
		out = p.ReplaceAllStringFunc(out, func(m string) string {
			i := strings.Index(m, ":")
			if i == -1 {
				return m
			}
			return m[:i+1] + "\"***\""
		})
	}
	return out
}

func (a *AuthlyX) createSecurityContext() (requestID, nonce string, timestampMs int64, err error) {
	requestID = newUUID()
	b := make([]byte, 16)
	_, err = rand.Read(b)
	if err != nil {
		return "", "", 0, err
	}
	nonce = hex.EncodeToString(b)
	timestampMs = time.Now().UnixMilli()
	return requestID, nonce, timestampMs, nil
}

func newUUID() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "00000000-0000-0000-0000-000000000000"
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	hexs := hex.EncodeToString(b)
	return hexs[0:8] + "-" + hexs[8:12] + "-" + hexs[12:16] + "-" + hexs[16:20] + "-" + hexs[20:32]
}

func (a *AuthlyX) buildURL(endpoint string) string {
	ep := strings.TrimLeft(endpoint, "/")
	return a.BaseURL + "/" + ep
}

func (a *AuthlyX) postJSON(endpoint string, payload map[string]any) (map[string]any, bool) {
	a.resetResponse()
	if payload == nil {
		a.setFailure("INVALID_PAYLOAD", "Payload cannot be null.", "", 0)
		return nil, false
	}

	requestID, nonce, ts, err := a.createSecurityContext()
	if err != nil {
		a.setFailure("SDK_ERROR", "Failed to create request metadata.", "", 0)
		return nil, false
	}

	payload["request_id"] = requestID
	payload["nonce"] = nonce
	payload["timestamp"] = ts

	bodyBytes, err := stableJSON(payload)
	if err != nil {
		a.setFailure("SDK_ERROR", "Failed to encode request.", "", 0)
		return nil, false
	}

	url := a.buildURL(endpoint)
	a.log("[SDK][REQUEST] POST " + url + " " + string(bodyBytes))

	req, err := http.NewRequest("POST", url, bytes.NewReader(bodyBytes))
	if err != nil {
		a.setFailure("SDK_ERROR", "Failed to create request.", "", 0)
		return nil, false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "AuthlyX-Go-Client/"+a.Version)
	req.Header.Set("x-request-id", requestID)
	req.Header.Set("x-auth-nonce", nonce)
	req.Header.Set("x-auth-timestamp", int64ToString(ts))

	resp, err := a.httpClient.Do(req)
	if err != nil {
		a.setFailure("NETWORK_ERROR", "Network error: "+err.Error(), "", 0)
		return nil, false
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	rawStr := string(raw)
	a.log("[SDK][RESPONSE] " + intToString(resp.StatusCode) + " " + rawStr)

	a.Response.Raw = rawStr
	a.Response.StatusCode = resp.StatusCode
	a.Response.RequestID = requestID
	a.Response.Nonce = nonce
	a.Response.SignatureKID = resp.Header.Get("x-v2-signature-kid")

	respReqID := resp.Header.Get("x-v2-request-id")
	if respReqID != "" && respReqID != requestID {
		a.setFailure("AUTH_REQUEST_MISMATCH", "Response request_id does not match the original request.", rawStr, resp.StatusCode)
		return nil, false
	}
	respNonce := resp.Header.Get("x-v2-nonce")
	if respNonce != "" && respNonce != nonce {
		a.setFailure("AUTH_REQUEST_MISMATCH", "Response nonce does not match the original request.", rawStr, resp.StatusCode)
		return nil, false
	}

	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		a.setFailure("INVALID_JSON", "Invalid JSON response from server.", rawStr, resp.StatusCode)
		return nil, false
	}

	canonicalResp, err := stableJSON(obj)
	if err != nil || !a.verifySignedResponse(resp.Header, requestID, nonce, string(canonicalResp)) {
		a.setFailure("AUTH_INVALID_SIGNATURE", "Response signature verification failed.", rawStr, resp.StatusCode)
		return nil, false
	}

	success, _ := obj["success"].(bool)
	a.Response.Success = success
	if msg, _ := obj["message"].(string); msg != "" {
		a.Response.Message = msg
	}
	if code, _ := obj["code"].(string); code != "" {
		a.Response.Code = code
	}
	if !a.Response.Success && a.Response.Code == "" {
		a.Response.Code = intToString(resp.StatusCode)
	}

	if sid, _ := obj["session_id"].(string); sid != "" {
		a.SessionID = sid
	}

	a.loadUserData(obj)
	a.loadVariableData(obj)
	a.loadUpdateData(obj)
	a.loadChatData(obj)

	return obj, a.Response.Success
}

func stableJSON(m map[string]any) ([]byte, error) {
	return stableValue(m)
}

func stableValue(v any) ([]byte, error) {
	switch typed := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for k := range typed {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf := bytes.NewBufferString("{")
		for i, k := range keys {
			if i > 0 {
				buf.WriteString(",")
			}
			keyBytes, _ := json.Marshal(k)
			valBytes, err := stableValue(typed[k])
			if err != nil {
				return nil, err
			}
			buf.Write(keyBytes)
			buf.WriteString(":")
			buf.Write(valBytes)
		}
		buf.WriteString("}")
		return buf.Bytes(), nil
	case []any:
		buf := bytes.NewBufferString("[")
		for i, item := range typed {
			if i > 0 {
				buf.WriteString(",")
			}
			itemBytes, err := stableValue(item)
			if err != nil {
				return nil, err
			}
			buf.Write(itemBytes)
		}
		buf.WriteString("]")
		return buf.Bytes(), nil
	default:
		return json.Marshal(v)
	}
}

func (a *AuthlyX) verifySignedResponse(headers http.Header, requestID, nonce, canonicalBody string) bool {
	signature := headers.Get("x-v2-signature")
	if signature == "" {
		signature = headers.Get("x-auth-signature")
	}
	signatureTs := headers.Get("x-v2-signature-ts")
	if signature == "" || signatureTs == "" {
		return !a.RequireSignedResponses
	}
	if strings.TrimSpace(a.ServerPublicKeyDerBase64) == "" {
		return !a.RequireSignedResponses
	}

	der, err := base64.StdEncoding.DecodeString(a.ServerPublicKeyDerBase64)
	if err != nil {
		return false
	}
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return false
	}
	publicKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false
	}
	payload := []byte(signatureTs + "\n" + requestID + "\n" + nonce + "\n" + canonicalBody)
	return ed25519.Verify(publicKey, payload, sig)
}

func int64ToString(v int64) string {
	return strconvFormatInt(v)
}

func intToString(v int) string {
	return strconvFormatInt(int64(v))
}

func strconvFormatInt(v int64) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var digits [32]byte
	i := len(digits)
	for v > 0 {
		i--
		digits[i] = byte('0' + (v % 10))
		v /= 10
	}
	if neg {
		i--
		digits[i] = '-'
	}
	return string(digits[i:])
}

func (a *AuthlyX) Init() bool {
	if strings.TrimSpace(a.OwnerID) == "" || strings.TrimSpace(a.AppName) == "" || strings.TrimSpace(a.Version) == "" || strings.TrimSpace(a.Secret) == "" {
		return a.setFailure("MISSING_CREDENTIALS", "Owner ID, app name, version, and secret are required.", "", 0)
	}

	payload := map[string]any{
		"owner_id": a.OwnerID,
		"app_name": a.AppName,
		"version":  a.Version,
		"secret":   a.Secret,
		"hash":     a.GetCurrentApplicationHash(),
	}

	_, ok := a.postJSON("init", payload)
	a.promptUpdateIfNeeded(strings.EqualFold(a.Response.Code, "UPDATE_REQUIRED"))
	if ok && a.SessionID != "" {
		a.Initialized = true
	}
	return a.Initialized
}

func (a *AuthlyX) Login(identifier, password, deviceType string) bool {
	if deviceType != "" {
		return a.DeviceLogin(deviceType, identifier)
	}
	if password == "" {
		return a.LicenseLogin(identifier)
	}
	return a.UserLogin(identifier, password)
}

func (a *AuthlyX) UserLogin(username, password string) bool {
	if !a.ensureInitialized() {
		return false
	}
	payload := map[string]any{
		"session_id": a.SessionID,
		"username":   username,
		"password":   password,
		"sid":        a.GetSystemIdentifier(),
		"ip":         a.GetPublicIP(),
	}
	_, ok := a.postJSON("login", payload)
	return ok
}

func (a *AuthlyX) LicenseLogin(licenseKey string) bool {
	if !a.ensureInitialized() {
		return false
	}
	payload := map[string]any{
		"session_id":  a.SessionID,
		"license_key": licenseKey,
		"sid":         a.GetSystemIdentifier(),
		"ip":          a.GetPublicIP(),
	}
	_, ok := a.postJSON("licenses", payload)
	return ok
}

func (a *AuthlyX) DeviceLogin(deviceType, deviceID string) bool {
	if !a.ensureInitialized() {
		return false
	}
	payload := map[string]any{
		"session_id":  a.SessionID,
		"device_type": strings.ToLower(strings.TrimSpace(deviceType)),
		"device_id":   deviceID,
		"ip":          a.GetPublicIP(),
	}
	_, ok := a.postJSON("device-auth", payload)
	return ok
}

func (a *AuthlyX) Register(username, password, licenseKey, email string) bool {
	if !a.ensureInitialized() {
		return false
	}
	payload := map[string]any{
		"session_id": a.SessionID,
		"username":   username,
		"password":   password,
		"key":        licenseKey,
		"email":      email,
		"hwid":       a.GetSystemIdentifier(),
	}
	_, ok := a.postJSON("register", payload)
	return ok
}

func (a *AuthlyX) ChangePassword(oldPassword, newPassword string) bool {
	if !a.ensureInitialized() {
		return false
	}
	payload := map[string]any{
		"session_id":   a.SessionID,
		"old_password": oldPassword,
		"new_password": newPassword,
	}
	_, ok := a.postJSON("change-password", payload)
	return ok
}

func (a *AuthlyX) ExtendTime(username, licenseKey string) bool {
	if !a.ensureInitialized() {
		return false
	}
	payload := map[string]any{
		"session_id":  a.SessionID,
		"username":    username,
		"license_key": licenseKey,
		"sid":         a.GetSystemIdentifier(),
		"ip":          a.GetPublicIP(),
	}
	_, ok := a.postJSON("extend", payload)
	return ok
}

func (a *AuthlyX) GetVariable(key string) (string, bool) {
	if !a.ensureInitialized() {
		return "", false
	}
	payload := map[string]any{
		"session_id": a.SessionID,
		"var_key":    key,
	}
	_, ok := a.postJSON("variables", payload)
	if !ok {
		return "", false
	}
	return a.VariableData.VarValue, true
}

func (a *AuthlyX) SetVariable(key, value string) bool {
	if !a.ensureInitialized() {
		return false
	}
	payload := map[string]any{
		"session_id": a.SessionID,
		"var_key":    key,
		"var_value":  value,
	}
	_, ok := a.postJSON("variables/set", payload)
	return ok
}

func (a *AuthlyX) Log(message string) bool {
	if !a.ensureInitialized() {
		return false
	}
	payload := map[string]any{
		"session_id": a.SessionID,
		"message":    message,
	}
	_, ok := a.postJSON("logs", payload)
	return ok
}

func (a *AuthlyX) SendChat(message, channelName string) bool {
	if !a.ensureInitialized() {
		return false
	}
	payload := map[string]any{
		"session_id": a.SessionID,
		"message":    message,
	}
	if strings.TrimSpace(channelName) != "" {
		payload["channel_name"] = channelName
	}
	_, ok := a.postJSON("chats/send", payload)
	return ok
}

func (a *AuthlyX) GetChats(channelName string, limit int, cursor string) bool {
	if !a.ensureInitialized() {
		return false
	}
	if limit <= 0 {
		limit = 100
	}
	payload := map[string]any{
		"session_id":   a.SessionID,
		"channel_name": channelName,
		"limit":        limit,
	}
	if strings.TrimSpace(cursor) != "" {
		payload["cursor"] = cursor
	}
	_, ok := a.postJSON("chats/get", payload)
	return ok
}

func (a *AuthlyX) ValidateSession() bool {
	if !a.Initialized || a.SessionID == "" {
		return a.setFailure("INVALID_SESSION", "No active session. Please login first.", "", 0)
	}
	payload := map[string]any{
		"session_id": a.SessionID,
	}
	_, ok := a.postJSON("validate-session", payload)
	return ok
}

func (a *AuthlyX) GetSessionId() string {
	return a.SessionID
}

func (a *AuthlyX) IsInitialized() bool {
	return a.Initialized
}

func (a *AuthlyX) GetCurrentApplicationHash() string {
	p, _ := os.Executable()
	if p == "" {
		return "UNKNOWN_HASH"
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return "UNKNOWN_HASH"
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (a *AuthlyX) GetSystemIdentifier() string {
	if runtime.GOOS == "windows" {
		if sid := getWindowsSID(); sid != "" {
			return sid
		}
	}
	u := os.Getenv("USERNAME")
	if u == "" {
		u = os.Getenv("USER")
	}
	h, _ := os.Hostname()
	seed := u + "|" + h + "|" + runtime.GOOS
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:])
}

func getWindowsSID() string {
	cmd := exec.Command("whoami", "/user", "/fo", "csv", "/nh")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	r := csv.NewReader(bytes.NewReader(bytes.TrimSpace(out)))
	rec, err := r.Read()
	if err != nil {
		return ""
	}
	for _, c := range rec {
		c = strings.Trim(strings.TrimSpace(c), "\"")
		if strings.HasPrefix(c, "S-1-") {
			return c
		}
	}
	if len(rec) >= 2 {
		c := strings.Trim(strings.TrimSpace(rec[1]), "\"")
		if strings.HasPrefix(c, "S-1-") {
			return c
		}
	}
	return ""
}

func (a *AuthlyX) GetPublicIP() string {
	if a.CachedPublicIP != "" && time.Now().Before(a.CachedIPExpires) {
		return a.CachedPublicIP
	}
	req, err := http.NewRequest("GET", "https://api.ipify.org", nil)
	if err != nil {
		return a.CachedPublicIP
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return a.CachedPublicIP
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	ip := strings.TrimSpace(string(b))
	if ip != "" {
		a.CachedPublicIP = ip
		a.CachedIPExpires = time.Now().Add(10 * time.Minute)
	}
	return a.CachedPublicIP
}

func (a *AuthlyX) loadUserData(obj map[string]any) {
	user, _ := obj["user"].(map[string]any)
	lic, _ := obj["license"].(map[string]any)
	dev, _ := obj["device"].(map[string]any)

	if user != nil {
		a.UserData.Username = toString(user["username"])
		a.UserData.Email = firstNonEmpty(toString(user["email"]), a.UserData.Email)
		a.UserData.Subscription = firstNonEmpty(toString(user["subscription"]), a.UserData.Subscription)
		a.UserData.SubscriptionLevel = firstNonEmpty(toString(user["subscription_level"]), a.UserData.SubscriptionLevel)
		a.UserData.ExpiryDate = firstNonEmpty(toString(user["expiry_date"]), a.UserData.ExpiryDate)
		a.UserData.LastLogin = firstNonEmpty(toString(user["last_login"]), a.UserData.LastLogin)
		a.UserData.RegisteredAt = firstNonEmpty(toString(user["created_at"]), a.UserData.RegisteredAt)
	}

	if lic != nil {
		a.UserData.LicenseKey = firstNonEmpty(toString(lic["license_key"]), a.UserData.LicenseKey)
		a.UserData.Subscription = firstNonEmpty(a.UserData.Subscription, toString(lic["subscription"]))
		a.UserData.SubscriptionLevel = firstNonEmpty(a.UserData.SubscriptionLevel, toString(lic["subscription_level"]))
		a.UserData.ExpiryDate = firstNonEmpty(a.UserData.ExpiryDate, toString(lic["expiry_date"]))
	}

	if dev != nil {
		a.UserData.Subscription = firstNonEmpty(a.UserData.Subscription, toString(dev["subscription"]))
		a.UserData.SubscriptionLevel = firstNonEmpty(a.UserData.SubscriptionLevel, toString(dev["subscription_level"]))
		a.UserData.ExpiryDate = firstNonEmpty(a.UserData.ExpiryDate, toString(dev["expiry_date"]))
		a.UserData.LastLogin = firstNonEmpty(a.UserData.LastLogin, toString(dev["last_login"]))
		a.UserData.RegisteredAt = firstNonEmpty(a.UserData.RegisteredAt, toString(dev["registered_at"]))
		a.UserData.IpAddress = firstNonEmpty(a.UserData.IpAddress, toString(dev["ip_address"]))
		a.UserData.Hwid = firstNonEmpty(a.UserData.Hwid, toString(dev["hwid"]))
	}

	if a.UserData.Hwid == "" {
		a.UserData.Hwid = a.GetSystemIdentifier()
	}
	if a.UserData.IpAddress == "" {
		a.UserData.IpAddress = a.GetPublicIP()
	}

	a.UserData.DaysLeft = computeDaysLeft(a.UserData.ExpiryDate)
}

func computeDaysLeft(expiry string) int {
	if strings.TrimSpace(expiry) == "" {
		return 0
	}
	t, err := time.Parse(time.RFC3339, strings.ReplaceAll(expiry, "Z", "+00:00"))
	if err != nil {
		return 0
	}
	d := int(t.Sub(time.Now().UTC()).Hours() / 24)
	if d < 0 {
		return 0
	}
	return d
}

func (a *AuthlyX) loadVariableData(obj map[string]any) {
	v, _ := obj["variable"].(map[string]any)
	if v == nil {
		return
	}
	a.VariableData.VarKey = toString(v["var_key"])
	a.VariableData.VarValue = toString(v["var_value"])
	a.VariableData.UpdatedAt = toString(v["updated_at"])
}

func (a *AuthlyX) loadUpdateData(obj map[string]any) {
	u, _ := obj["update"].(map[string]any)
	if u == nil {
		if obj["auto_update_enabled"] != nil || obj["auto_update_download_url"] != nil {
			a.UpdateData.Available = true
			a.UpdateData.LatestVersion = toString(obj["server_version"])
			if strings.TrimSpace(a.UpdateData.LatestVersion) == "" {
				a.UpdateData.LatestVersion = toString(obj["version"])
			}
			a.UpdateData.AutoUpdateEnabled = toBool(obj["auto_update_enabled"])
			a.UpdateData.DownloadUrl = toString(obj["auto_update_download_url"])
			a.UpdateData.ForceUpdate = toBool(obj["force_update"])
		}
		return
	}
	a.UpdateData.Available = toBool(u["available"])
	a.UpdateData.LatestVersion = toString(u["latest_version"])
	a.UpdateData.AutoUpdateEnabled = toBool(u["auto_update_enabled"])
	a.UpdateData.DownloadUrl = toString(u["download_url"])
	a.UpdateData.ForceUpdate = toBool(u["force_update"])
	a.UpdateData.Changelog = toString(u["changelog"])
	a.UpdateData.ShowReminder = toBool(u["show_reminder"])
	a.UpdateData.ReminderMessage = toString(u["reminder_message"])
	a.UpdateData.AllowedUntil = toString(u["allowed_until"])
}

func compareSemver(current, latest string) int {
	strip := func(s string) string {
		s = strings.TrimSpace(s)
		if i := strings.IndexByte(s, '-'); i >= 0 {
			s = s[:i]
		}
		return s
	}

	parse := func(s string) [3]int {
		s = strip(s)
		var out [3]int
		parts := strings.Split(s, ".")
		for i := 0; i < len(out) && i < len(parts); i++ {
			n := 0
			for _, r := range parts[i] {
				if r < '0' || r > '9' {
					break
				}
				n = n*10 + int(r-'0')
			}
			out[i] = n
		}
		return out
	}

	a := parse(current)
	b := parse(latest)
	for i := 0; i < 3; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

func stdinIsTerminal() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func openUrl(url string) {
	url = strings.TrimSpace(url)
	if url == "" {
		return
	}

	switch runtime.GOOS {
	case "windows":
		_ = exec.Command("cmd", "/c", "start", "", url).Start()
	case "darwin":
		_ = exec.Command("open", url).Start()
	default:
		_ = exec.Command("xdg-open", url).Start()
	}
}

func (a *AuthlyX) shouldShowUpdatePrompt(forceShow bool) bool {
	if !a.UpdateData.Available {
		return false
	}
	if forceShow {
		return true
	}
	if !a.isClientOutdated() {
		return false
	}
	if !a.hasWhitelistedUpdateMessage() {
		return false
	}
	return true
}

func (a *AuthlyX) isClientOutdated() bool {
	if strings.TrimSpace(a.UpdateData.LatestVersion) == "" {
		return false
	}
	return compareSemver(a.Version, a.UpdateData.LatestVersion) < 0
}

func (a *AuthlyX) hasWhitelistedUpdateMessage() bool {
	return a.UpdateData.ShowReminder || strings.TrimSpace(a.UpdateData.AllowedUntil) != ""
}

func (a *AuthlyX) isAutoUpdateEnabled() bool {
	return a.UpdateData.AutoUpdateEnabled
}

func formatDisplayDate(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return raw
	}
	t, err := time.Parse(time.RFC3339, strings.ReplaceAll(raw, "Z", "+00:00"))
	if err != nil {
		return raw
	}
	return t.Format("January 2, 2006")
}

func (a *AuthlyX) buildWhitelistedUpdateMessage() string {
	if strings.TrimSpace(a.UpdateData.AllowedUntil) != "" {
		base := fmt.Sprintf("A new version is ready, and you can keep using this build until %s.", formatDisplayDate(a.UpdateData.AllowedUntil))
		if !a.isAutoUpdateEnabled() {
			return base
		}
		return base + "\n\nWould you like to download the latest version now?"
	}

	base := "A new version is ready, and you can still use this build for now."
	if !a.isAutoUpdateEnabled() {
		return base
	}
	return base + "\n\nWould you like to download the latest version now?"
}

func escapePowerShellString(value string) string {
	return strings.ReplaceAll(value, "'", "''")
}

func tryShowWindowsMessageBox(message string, yesNo bool) (string, bool) {
	if runtime.GOOS != "windows" {
		return "", false
	}

	button := "OK"
	if yesNo {
		button = "YesNo"
	}
	script := fmt.Sprintf(
		"Add-Type -AssemblyName PresentationFramework; $result = [System.Windows.MessageBox]::Show('%s', 'AuthlyX Update', [System.Windows.MessageBoxButton]::%s, [System.Windows.MessageBoxImage]::Information); Write-Output $result",
		escapePowerShellString(message),
		button,
	)
	out, err := exec.Command("powershell", "-NoProfile", "-Command", script).CombinedOutput()
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(out)), true
}

func (a *AuthlyX) showRequiredUpdateConsole() {
	message := strings.TrimSpace(a.Response.Message)
	if message == "" {
		message = "Please update your app to the latest version."
	}
	fmt.Println(message)

	if strings.TrimSpace(a.UpdateData.LatestVersion) != "" {
		fmt.Printf("Latest version: %s\n", strings.TrimSpace(a.UpdateData.LatestVersion))
	}

	if !a.isAutoUpdateEnabled() || strings.TrimSpace(a.UpdateData.DownloadUrl) == "" {
		return
	}

	fmt.Println("1. Download Latest")
	fmt.Println("2. Exit")

	if !stdinIsTerminal() {
		return
	}

	fmt.Print("Select an option (1 or 2): ")
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "1" {
		openUrl(strings.TrimSpace(a.UpdateData.DownloadUrl))
	}
}

func (a *AuthlyX) promptUpdateIfNeeded(forceShow bool) {
	if !a.shouldShowUpdatePrompt(forceShow) {
		return
	}

	if forceShow {
		a.showRequiredUpdateConsole()
		return
	}

	msg := a.buildWhitelistedUpdateMessage()
	downloadUrl := strings.TrimSpace(a.UpdateData.DownloadUrl)
	useDownloadPrompt := a.isAutoUpdateEnabled() && downloadUrl != ""

	if result, ok := tryShowWindowsMessageBox(msg, useDownloadPrompt); ok {
		if useDownloadPrompt && strings.EqualFold(strings.TrimSpace(result), "Yes") {
			openUrl(downloadUrl)
		}
		return
	}

	fmt.Println(msg)
	if !useDownloadPrompt {
		return
	}

	if !stdinIsTerminal() {
		return
	}

	fmt.Print("Download the latest version now? (Y/N): ")
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(strings.ToLower(line))
	if line == "y" || line == "yes" {
		openUrl(downloadUrl)
	}
}

func (a *AuthlyX) loadChatData(obj map[string]any) {
	data, _ := obj["data"].(map[string]any)
	if data == nil {
		return
	}
	a.ChatMessages.ChannelName = toString(data["channel_name"])
	a.ChatMessages.NextCursor = toString(data["next_cursor"])
	a.ChatMessages.HasMore = toBool(data["has_more"])

	msgs, _ := data["messages"].([]any)
	out := make([]ChatMessage, 0)
	for _, m := range msgs {
		mm, ok := m.(map[string]any)
		if !ok {
			continue
		}
		out = append(out, ChatMessage{
			ID:        mm["id"],
			Username:  toString(mm["username"]),
			Message:   toString(mm["message"]),
			CreatedAt: toString(mm["created_at"]),
		})
	}
	a.ChatMessages.Messages = out
	a.ChatMessages.Count = len(out)
}

func toString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case float64:
		b, _ := json.Marshal(t)
		return string(b)
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}

func toBool(v any) bool {
	b, ok := v.(bool)
	if ok {
		return b
	}
	return false
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
