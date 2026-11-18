// AuthlyX Go SDK Version 3.0 BETA
package authlyx

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

type Error struct {
	Code, Message, Kind, RequestID string
	Status                         int
	Data                           map[string]any
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }
func failure(code, message, kind string) *Error {
	return &Error{Code: code, Message: message, Kind: kind}
}

type Result struct {
	Success   bool           `json:"success"`
	Code      string         `json:"code"`
	Message   string         `json:"message"`
	RequestID string         `json:"requestId"`
	Data      map[string]any `json:"data"`
}

func (r Result) String() string { return r.Code }

func DecodeData[T any](r Result) (T, error) {
	var result T
	b, e := json.Marshal(r.Data)
	if e == nil {
		e = json.Unmarshal(b, &result)
	}
	return result, e
}

type Store interface {
	Load(context.Context, string) (string, error)
	Save(context.Context, string, string) error
	Delete(context.Context, string) error
}
type MemoryStore struct {
	mu     sync.Mutex
	values map[string]string
}

func (s *MemoryStore) Load(_ context.Context, k string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.values[k], nil
}
func (s *MemoryStore) Save(_ context.Context, k, v string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.values == nil {
		s.values = map[string]string{}
	}
	s.values[k] = v
	return nil
}
func (s *MemoryStore) Delete(_ context.Context, k string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.values, k)
	return nil
}

type Options struct {
	Heartbeat                                      string
	AppKey, Version, SystemID, BuildHash, Endpoint string
	ResponseKeys, OfflineKeys, ScriptKeys          map[string]string
	Storage                                        Store
	RequestBudget                                  time.Duration
	ManualHeartbeat, AllowLocalHTTP, NoUpdatePrompt bool
	OnConnection                                   func(string)
	OnInvalidated                                  func(*Error)
}
type offlineState struct {
	AppID       string            `json:"appId"`
	IdentityID  string            `json:"identityId"`
	Kind        string            `json:"kind"`
	Salt        string            `json:"salt"`
	Verifier    string            `json:"verifier"`
	Permit      map[string]string `json:"permit"`
	TrustedTime int64             `json:"trustedTime"`
	LocalTime   int64             `json:"localTime"`
	UserData    map[string]any    `json:"userData,omitempty"`
}
type AuthlyX struct {
	userData                                                                 map[string]any
	o                                                                        Options
	http                                                                     *http.Client
	key                                                                      ed25519.PrivateKey
	publicPEM, installationHash, prefix, token, sessionID, appID, identityID string
	offline, credential                                                      *offlineState
	slot                                                                     string
	offlineSession, updateOffered                                            bool
	serverTime, wallTime                                                     int64
	anchor                                                                   time.Time
	deadline                                                                 int64
	heartbeatSeconds, jitterSeconds                                          float64
	gate                                                                     chan struct{}
	life                                                                     context.Context
	cancel                                                                   context.CancelFunc
	heartbeatCancel                                                          context.CancelFunc
	disposed, loggingOut                                                     bool
	events                                                                   chan func()
}

func hash(v []byte) string { sum := sha256.Sum256(v); return hex.EncodeToString(sum[:]) }
func random(n int) []byte {
	v := make([]byte, n)
	if _, e := rand.Read(v); e != nil {
		panic("OS random source unavailable")
	}
	return v
}
func publicKey(value string) (ed25519.PublicKey, error) {
	b, _ := pem.Decode([]byte(value))
	if b == nil {
		return nil, errors.New("invalid public key")
	}
	k, e := x509.ParsePKIXPublicKey(b.Bytes)
	if e != nil {
		return nil, e
	}
	p, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("not Ed25519")
	}
	return p, nil
}
func fingerprint(k ed25519.PublicKey) string { b, _ := x509.MarshalPKIXPublicKey(k); return hash(b) }
func verifySignature(value, payload, signature string) bool {
	k, e := publicKey(value)
	if e != nil {
		return false
	}
	sig, e := base64.StdEncoding.DecodeString(signature)
	return e == nil && ed25519.Verify(k, []byte(payload), sig)
}
func quote(v string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range v {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 32 {
				fmt.Fprintf(&b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

type pair struct{ k, v string }

func object(fields ...pair) string {
	var b strings.Builder
	b.WriteByte('{')
	for i, p := range fields {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(quote(p.k))
		b.WriteByte(':')
		b.WriteString(p.v)
	}
	b.WriteByte('}')
	return b.String()
}
func text(k, v string) pair    { return pair{k, quote(v)} }
func stringValue(v any) string { s, _ := v.(string); return s }
func number(v any) float64 {
	switch n := v.(type) {
	case json.Number:
		f, _ := n.Float64()
		return f
	case float64:
		return n
	}
	return 0
}
func decode(b []byte) (map[string]any, error) {
	var v map[string]any
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	e := d.Decode(&v)
	if e == nil {
		var extra any
		if d.Decode(&extra) != io.EOF {
			return nil, failure("RESPONSE_INVALID", "Unexpected trailing JSON.", "security")
		}
	}
	return v, e
}
func clone(v map[string]string) map[string]string {
	r := map[string]string{}
	for k, p := range v {
		r[k] = p
	}
	return r
}
func New(ctx context.Context, o Options) (*AuthlyX, error) {
	if o.Heartbeat != "" {
		if o.Heartbeat != "server" && o.Heartbeat != "manual" {
			return nil, errors.New("use server or manual heartbeat mode")
		}
		o.ManualHeartbeat = o.Heartbeat == "manual"
	}
	u, e := url.Parse(o.Endpoint)
	if e != nil {
		return nil, e
	}
	local := u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost" || u.Hostname() == "::1"
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || (u.Scheme != "https" && !(o.AllowLocalHTTP && u.Scheme == "http" && local)) {
		return nil, errors.New("use an HTTPS API origin; HTTP is limited to explicit loopback testing")
	}
	if o.Storage == nil || o.AppKey == "" || o.Version == "" || o.SystemID == "" || len(o.ResponseKeys) == 0 {
		return nil, errors.New("provide app identity, protected storage and trusted response keys")
	}
	if o.RequestBudget == 0 {
		o.RequestBudget = 8 * time.Second
	}
	if o.RequestBudget < 100*time.Millisecond || o.RequestBudget > time.Minute {
		return nil, errors.New("request budget must be 100 ms to 60 seconds")
	}
	o.ResponseKeys = clone(o.ResponseKeys)
	o.OfflineKeys = clone(o.OfflineKeys)
	o.ScriptKeys = clone(o.ScriptKeys)
	o.Endpoint = u.Scheme + "://" + u.Host
	life, cancel := context.WithCancel(context.Background())
	c := &AuthlyX{o: o, gate: make(chan struct{}, 1), life: life, cancel: cancel, heartbeatSeconds: 600, jitterSeconds: 15, events: make(chan func(), 32)}
	c.http = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, ForceAttemptHTTP2: true, TLSHandshakeTimeout: o.RequestBudget}}
	c.prefix = "authlyx.v3." + hash([]byte(o.Endpoint+"/\n"+o.AppKey+"\n"+o.SystemID))
	identityName := "authlyx.v3.installation." + hash([]byte(o.Endpoint+"/\n"+o.SystemID))
	saved, e := o.Storage.Load(ctx, identityName)
	if e != nil {
		return nil, failure("STORAGE_INVALID", "Protected state could not be read.", "storage")
	}
	var seed []byte
	if saved == "" {
		seed = random(32)
		e = o.Storage.Save(ctx, identityName, base64.StdEncoding.EncodeToString(seed))
	} else {
		seed, e = base64.StdEncoding.DecodeString(saved)
	}
	if e != nil || len(seed) != 32 {
		return nil, failure("STORAGE_INVALID", "Protected installation key is invalid.", "storage")
	}
	c.key = ed25519.NewKeyFromSeed(seed)
	for i := range seed {
		seed[i] = 0
	}
	pub := c.key.Public().(ed25519.PublicKey)
	der, _ := x509.MarshalPKIXPublicKey(pub)
	c.publicPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	c.installationHash = hash(der)
	go func() {
		for {
			select {
			case f := <-c.events:
				func() { defer func() { _ = recover() }(); f() }()
			case <-c.life.Done():
				return
			}
		}
	}()
	return c, nil
}
func (c *AuthlyX) lock(ctx context.Context) error {
	select {
	case c.gate <- struct{}{}:
		if c.disposed {
			<-c.gate
			return failure("DISPOSED", "This client is disposed.", "cancelled")
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-c.life.Done():
		return c.life.Err()
	}
}
func (c *AuthlyX) unlock() { <-c.gate }
func (c *AuthlyX) setAnchor(ms int64) {
	c.serverTime = ms
	c.anchor = time.Now()
	c.wallTime = time.Now().UnixMilli()
}
func (c *AuthlyX) now() int64 {
	if c.serverTime == 0 {
		return time.Now().UnixMilli()
	}
	return c.serverTime + time.Since(c.anchor).Milliseconds()
}
func (c *AuthlyX) emit(f func()) {
	select {
	case c.events <- f:
	default:
	}
}
func (c *AuthlyX) connection(state string) {
	if c.o.OnConnection != nil {
		c.emit(func() { c.o.OnConnection(state) })
	}
}
func slotOf(kind, username, license string) string {
	id := ""
	if kind == "user" {
		id = strings.ToLower(strings.TrimSpace(username))
	} else if kind == "license" {
		id = strings.TrimSpace(license)
	}
	return hash([]byte(kind + "\n" + id))
}
func offlineVerifier(secret string, salt []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(salt)
	mac.Write([]byte{0, 0, 0, 1})
	u := mac.Sum(nil)
	out := append([]byte(nil), u...)
	for i := 1; i < 120000; i++ {
		mac.Reset()
		mac.Write(u)
		u = mac.Sum(u[:0])
		for j := range out {
			out[j] ^= u[j]
		}
	}
	return base64.StdEncoding.EncodeToString(out)
}
func (c *AuthlyX) recordName(slot string) string { return c.prefix + ".offline." + slot }
func (c *AuthlyX) slots(ctx context.Context) []string {
	var list struct {
		Slots []string `json:"slots"`
	}
	saved, e := c.o.Storage.Load(ctx, c.prefix+".offline")
	if e != nil || saved == "" || json.Unmarshal([]byte(saved), &list) != nil {
		return nil
	}
	return list.Slots
}
func (c *AuthlyX) saveSlots(ctx context.Context, list []string) error {
	if len(list) == 0 {
		return c.o.Storage.Delete(ctx, c.prefix+".offline")
	}
	b, e := json.Marshal(map[string][]string{"slots": list})
	if e != nil {
		return e
	}
	return c.o.Storage.Save(ctx, c.prefix+".offline", string(b))
}
func (c *AuthlyX) loadRecord(ctx context.Context, slot string) *offlineState {
	saved, e := c.o.Storage.Load(ctx, c.recordName(slot))
	if e != nil || saved == "" {
		return nil
	}
	var record offlineState
	if json.Unmarshal([]byte(saved), &record) != nil {
		return nil
	}
	return &record
}
func (c *AuthlyX) forget(ctx context.Context, slot string) error {
	if slot == "" {
		return nil
	}
	e := c.o.Storage.Delete(ctx, c.recordName(slot))
	kept := []string{}
	for _, item := range c.slots(ctx) {
		if item != slot {
			kept = append(kept, item)
		}
	}
	if s := c.saveSlots(ctx, kept); e == nil {
		e = s
	}
	return e
}
func (c *AuthlyX) clearOffline(ctx context.Context) error {
	c.offline = nil
	c.offlineSession = false
	return c.forget(ctx, c.slot)
}
func (c *AuthlyX) recordNow(r *offlineState) int64 {
	if c.serverTime != 0 {
		return c.now()
	}
	return r.TrustedTime + time.Now().UnixMilli() - r.LocalTime
}
func (c *AuthlyX) offlineLogin(ctx context.Context, kind, username, password, license string) (Result, error) {
	name := slotOf(kind, username, license)
	record := c.loadRecord(ctx, name)
	if record == nil || !c.validRecord(record) {
		if record != nil {
			_ = c.forget(ctx, name)
		}
		return Result{}, failure("OFFLINE_UNAVAILABLE", "Could not connect to AuthlyX, and this PC has no saved offline access for that account. Check your internet connection and try again.", "network")
	}
	if kind != "device" {
		secret := license
		if kind == "user" {
			secret = password
		}
		salt, e := base64.StdEncoding.DecodeString(record.Salt)
		if e != nil || subtle.ConstantTimeCompare([]byte(offlineVerifier(secret, salt)), []byte(record.Verifier)) != 1 {
			if kind == "user" {
				return Result{}, failure("INVALID_CREDENTIALS", "Username or password is incorrect.", "server")
			}
			return Result{}, failure("LICENSE_NOT_FOUND", "License not found.", "server")
		}
	}
	if c.serverTime == 0 {
		c.setAnchor(c.recordNow(record))
	}
	c.appID = record.AppID
	c.identityID = record.IdentityID
	c.slot = name
	c.offline = record
	c.offlineSession = true
	c.userData = record.UserData
	if c.userData == nil {
		c.userData = map[string]any{}
	}
	_ = c.persist(ctx)
	return Result{Success: true, Code: "OFFLINE_ACCESS", Message: "Signed in with saved offline access. Online features are unavailable until you reconnect.", Data: map[string]any{"offline": true, "identity": c.userData}}, nil
}
func (c *AuthlyX) invalidate(ctx context.Context, e *Error) {
	c.token = ""
	c.userData = nil
	c.deadline = 0
	c.stopHeartbeat()
	_ = c.clearOffline(ctx)
	if c.o.OnInvalidated != nil {
		c.emit(func() { c.o.OnInvalidated(e) })
	}
}
func (c *AuthlyX) verify(outer map[string]any, status int, path, body, nonce string) (Result, error) {
	bad := failure("RESPONSE_INVALID", "The server response could not be verified.", "security")
	proof, ok := outer["verification"].(map[string]any)
	if !ok {
		return Result{}, bad
	}
	id := stringValue(proof["keyId"])
	p := c.o.ResponseKeys[id]
	key, e := publicKey(p)
	payload := stringValue(proof["signedPayload"])
	if e != nil || fingerprint(key) != id || len(payload) > 2000000 || !verifySignature(p, payload, stringValue(proof["signature"])) {
		return Result{}, bad
	}
	signed, e := decode([]byte(payload))
	if e != nil {
		return Result{}, bad
	}
	request, ok := signed["request"].(map[string]any)
	if !ok {
		return Result{}, bad
	}
	delete(outer, "verification")
	if signed["type"] != "authlyx.response.v3" || signed["keyId"] != id || int(number(signed["httpStatus"])) != status || request["method"] != "POST" || request["path"] != path || request["nonce"] != nonce || request["bodySha256"] != hash([]byte(body)) || !reflect.DeepEqual(signed["response"], outer) {
		return Result{}, bad
	}
	server, e := time.Parse(time.RFC3339Nano, stringValue(signed["serverTime"]))
	if e != nil {
		return Result{}, bad
	}
	c.setAnchor(server.UnixMilli())
	_, messageOK := outer["message"].(string)
	success, ok := outer["success"].(bool)
	if !ok || !messageOK {
		return Result{}, bad
	}
	data, _ := outer["data"].(map[string]any)
	result := Result{Success: success, Code: stringValue(outer["code"]), Message: stringValue(outer["message"]), RequestID: stringValue(outer["requestId"]), Data: data}
	if result.Code == "" || result.RequestID == "" {
		return Result{}, bad
	}
	return result, nil
}
func (c *AuthlyX) request(ctx context.Context, path, body string, auth, retry bool) (Result, error) {
	if auth && c.token == "" {
		return Result{}, failure("NOT_SIGNED_IN", "Sign in before using this feature.", "server")
	}
	budget, cancel := context.WithTimeout(ctx, c.o.RequestBudget)
	defer cancel()
	goCancel := context.AfterFunc(c.life, cancel)
	defer goCancel()
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		nonce := hex.EncodeToString(random(24))
		stamp := strconv.FormatInt(c.now(), 10)
		request, e := http.NewRequestWithContext(budget, "POST", c.o.Endpoint+path, strings.NewReader(body))
		if e != nil {
			return Result{}, e
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-AuthlyX-Nonce", nonce)
		if auth {
			proof := object(text("type", "authlyx.request.v3"), text("method", "POST"), text("path", path), text("bodySha256", hash([]byte(body))), text("nonce", nonce), text("timestamp", stamp), text("tokenHash", hash([]byte(c.token))))
			request.Header.Set("Authorization", "Bearer "+c.token)
			request.Header.Set("X-AuthlyX-Timestamp", stamp)
			request.Header.Set("X-AuthlyX-Signature", base64.StdEncoding.EncodeToString(ed25519.Sign(c.key, []byte(proof))))
		}
		response, e := c.http.Do(request)
		delay := 150 * time.Millisecond
		if e != nil {
			if ctx.Err() != nil {
				return Result{}, ctx.Err()
			}
			last = failure("NETWORK_ERROR", "Could not connect to AuthlyX.", "network")
		} else {
			data, readError := io.ReadAll(io.LimitReader(response.Body, 2000001))
			_ = response.Body.Close()
			if readError != nil {
				last = failure("NETWORK_ERROR", "Could not read the server response.", "network")
			} else if len(data) > 2000000 {
				last = failure("RESPONSE_INVALID", "The server response is too large.", "security")
			} else {
				outer, parseError := decode(data)
				if (parseError != nil || outer["verification"] == nil) && response.StatusCode >= 500 {
					last = failure("SERVICE_UNAVAILABLE", "The service is temporarily unavailable.", "network")
				} else if parseError != nil {
					last = failure("RESPONSE_INVALID", "The server response is not valid JSON.", "security")
				} else {
					result, verifyError := c.verify(outer, response.StatusCode, path, body, nonce)
					if verifyError != nil {
						last = verifyError
					} else if response.StatusCode >= 400 || !result.Success {
						kind := "server"
						if response.StatusCode == 429 || response.StatusCode >= 500 {
							kind = "network"
						}
						last = &Error{Code: result.Code, Message: result.Message, Kind: kind, Status: response.StatusCode, RequestID: result.RequestID, Data: result.Data}
						if result.Code == "REQUEST_TIME_INVALID" && retry && attempt < 2 {
							continue
						}
					} else {
						c.connection("online")
						return result, nil
					}
				}
			}
			if after := response.Header.Get("Retry-After"); after != "" {
				if n, e := strconv.Atoi(after); e == nil {
					delay = time.Duration(n) * time.Second
				} else if t, e := http.ParseTime(after); e == nil {
					delay = time.Until(t)
				} else {
					delay = c.o.RequestBudget
				}
			}
		}
		var problem *Error
		if errors.As(last, &problem) {
			if problem.Kind == "security" {
				c.connection("untrusted")
				c.invalidate(context.Background(), problem)
				return Result{}, last
			}
			if problem.Kind == "server" {
				if auth && (problem.Code == "SESSION_EXPIRED" || problem.Code == "ACCESS_REVOKED" || problem.Code == "APP_PAUSED" || problem.Code == "ACCESS_EXPIRED" || problem.Code == "ACCESS_DENIED" || problem.Code == "IP_BLACKLISTED" || problem.Code == "IP_NOT_WHITELISTED" || problem.Code == "SID_BLACKLISTED" || problem.Code == "SID_NOT_WHITELISTED" || problem.Code == "VERSION_NOT_ALLOWED" || problem.Code == "HASH_NOT_ALLOWED" || problem.Code == "COUNTRY_BLOCKED" || problem.Code == "VPN_NOT_ALLOWED" || problem.Code == "DEVICE_NOT_ALLOWED" || problem.Code == "APP_DISABLED" || problem.Code == "IP_BLOCKED" || problem.Code == "SID_BLOCKED" || problem.Code == "UPDATE_REQUIRED" || problem.Code == "VERSION_MISMATCH" || problem.Code == "INVALID_HASH" || problem.Code == "VPN_BLOCKED" || problem.Code == "USER_BANNED" || problem.Code == "USER_SUSPENDED" || problem.Code == "USER_EXPIRED" || problem.Code == "LICENSE_BANNED" || problem.Code == "LICENSE_PAUSED" || problem.Code == "LICENSE_EXPIRED" || problem.Code == "MOTHERBOARD_BANNED" || problem.Code == "MOTHERBOARD_PAUSED" || problem.Code == "MOTHERBOARD_EXPIRED" || problem.Code == "PROCESSOR_BANNED" || problem.Code == "PROCESSOR_PAUSED" || problem.Code == "PROCESSOR_EXPIRED") {
					c.invalidate(context.Background(), problem)
				}
				return Result{}, last
			}
		}
		c.connection("disconnected")
		if budget.Err() != nil {
			return Result{}, failure("NETWORK_TIMEOUT", "The request timed out. Try again when connected.", "network")
		}
		until, _ := budget.Deadline()
		if !retry || attempt == 2 || delay < 0 || time.Until(until) < delay+50*time.Millisecond {
			return Result{}, last
		}
		select {
		case <-time.After(delay):
		case <-budget.Done():
			if ctx.Err() != nil {
				return Result{}, ctx.Err()
			}
			return Result{}, failure("NETWORK_TIMEOUT", "The request timed out.", "network")
		}
	}
	return Result{}, last
}
func (c *AuthlyX) Initialize(ctx context.Context) (Result, error) { return c.Init(ctx) }
func (c *AuthlyX) InitializeAsync(ctx context.Context, callback func(Result)) error {
	return c.InitAsync(ctx, callback)
}
func (c *AuthlyX) Init(ctx context.Context) (Result, error) {
	if e := c.lock(ctx); e != nil {
		return Result{}, e
	}
	result, err := c.request(ctx, "/v3/initialize", object(text("appKey", c.o.AppKey), text("version", c.o.Version)), false, true)
	c.unlock()
	var problem *Error
	if err == nil || !errors.As(err, &problem) {
		return result, err
	}
	if problem.Kind == "network" {
		if c.HasOfflineAccess(ctx) {
			return Result{Success: true, Code: "OFFLINE_MODE", Message: "You are offline. Sign in with the account you saved offline access for.", Data: map[string]any{}}, nil
		}
		return Result{Code: problem.Code, Message: "Could not connect to AuthlyX. Check your internet connection.", RequestID: problem.RequestID}, nil
	}
	if problem.Kind != "server" {
		return result, err
	}
	c.offerUpdate(problem.Data, problem.Code, problem.Message, true)
	return Result{Code: problem.Code, Message: problem.Message, RequestID: problem.RequestID, Data: problem.Data}, nil
}
func (c *AuthlyX) offerUpdate(data map[string]any, code, message string, wait bool) {
	if c.o.NoUpdatePrompt || data == nil {
		return
	}
	update, ok := data["update"].(map[string]any)
	if !ok {
		return
	}
	link, latest, notes := stringValue(update["url"]), stringValue(update["version"]), stringValue(update["notes"])
	if !strings.HasPrefix(link, "https://") && !strings.HasPrefix(link, "http://") {
		link = ""
	}
	required := code == "UPDATE_REQUIRED" || code == "VERSION_MISMATCH"
	if !required {
		if available, _ := data["updateAvailable"].(bool); c.updateOffered || !available || link == "" {
			return
		}
		c.updateOffered = true
	}
	body := message
	if !required {
		body = "Version " + latest + " is available."
	}
	body += "\n\nYour version: " + c.o.Version
	if latest != "" {
		body += "\nLatest version: " + latest
	}
	if notes != "" {
		body += "\n\n" + notes
	}
	if link != "" {
		body += "\n\nOpen the download page?"
	}
	heading := "Update available"
	if code == "UPDATE_REQUIRED" {
		heading = "Update required"
	} else if code == "VERSION_MISMATCH" {
		heading = "Version not supported"
	}
	if wait {
		showUpdate(heading, body, link)
	} else {
		go showUpdate(heading, body, link)
	}
}
func (c *AuthlyX) UserData(ctx context.Context) (map[string]any, error) {
	if e := c.lock(ctx); e != nil {
		return nil, e
	}
	defer c.unlock()
	encoded, e := json.Marshal(c.userData)
	if e != nil {
		return nil, e
	}
	var data map[string]any
	e = json.Unmarshal(encoded, &data)
	return data, e
}
func (c *AuthlyX) RegisterUser(ctx context.Context, username, password, licenseKey string) (Result, error) {
	return c.login(ctx, "register", username, password, licenseKey)
}
func (c *AuthlyX) ChangePassword(ctx context.Context, currentPassword, newPassword string) (Result, error) {
	return c.protected(ctx, "/v3/account/password", object(text("currentPassword", currentPassword), text("newPassword", newPassword)), false)
}
func (c *AuthlyX) RedeemLicense(ctx context.Context, licenseKey string) (Result, error) {
	return c.protected(ctx, "/v3/licenses/redeem", object(text("licenseKey", licenseKey)), false)
}
func (c *AuthlyX) Log(ctx context.Context, message string) (Result, error) {
	return c.protected(ctx, "/v3/logs/add", object(text("message", message)), false)
}
func (c *AuthlyX) Login(ctx context.Context, username, password string) (Result, error) {
	return c.login(ctx, "user", username, password, "")
}
func (c *AuthlyX) LicenseLogin(ctx context.Context, license string) (Result, error) {
	return c.login(ctx, "license", "", "", license)
}
func (c *AuthlyX) DeviceLogin(ctx context.Context) (Result, error) {
	return c.login(ctx, "device", "", "", "")
}
func (c *AuthlyX) login(ctx context.Context, kind, username, password, license string) (Result, error) {
	if !utf8.ValidString(username) || !utf8.ValidString(password) {
		return Result{}, errors.New("credentials must be valid UTF-8")
	}
	if e := c.lock(ctx); e != nil {
		return Result{}, e
	}
	defer c.unlock()
	if c.token != "" || c.offlineSession {
		return Result{}, failure("ALREADY_SIGNED_IN", "Sign out before starting another session.", "server")
	}
	c.loggingOut = false
	challenge, e := c.request(ctx, "/v3/challenge", object(text("appKey", c.o.AppKey), text("installationPublicKey", c.publicPEM)), false, false)
	if e != nil {
		var problem *Error
		if errors.As(e, &problem) && problem.Kind == "network" && kind != "register" {
			return c.offlineLogin(ctx, kind, username, password, license)
		}
		return Result{}, e
	}
	payload := stringValue(challenge.Data["payload"])
	operation := object(text("type", kind), text("appKey", c.o.AppKey), text("version", c.o.Version), text("sid", c.o.SystemID), text("hash", c.o.BuildHash), text("username", username), text("password", password), text("licenseKey", license), pair{"device", deviceDetails()})
	proof := object(text("challenge", payload), pair{"operation", operation})
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(c.key, []byte(proof)))
	body := strings.TrimSuffix(operation, "}") + "," + quote("challengeId") + ":" + quote(stringValue(challenge.Data["challengeId"])) + "," + quote("signature") + ":" + quote(signature) + "}"
	result, e := c.request(ctx, "/v3/login", body, false, false)
	if e != nil {
		return Result{}, e
	}
	claims, e := decode([]byte(payload))
	if e != nil {
		return Result{}, e
	}
	c.appID = stringValue(claims["appId"])
	c.token = stringValue(result.Data["token"])
	c.sessionID = stringValue(result.Data["sessionId"])
	c.identityID = stringValue(result.Data["identityId"])
	c.userData = result.Data["identity"].(map[string]any)
	for dest, src := range map[string]string{"SID": "systemId", "Email": "email", "Plan": "plan", "ExpiryDate": "expiry", "Country": "country", "IpAddress": "ipAddress", "DeviceLimit": "deviceLimit", "LicenseKey": "licenseKey"} {
		c.userData[dest] = c.userData[src]
	}
	if c.userData["type"] == "user" {
		c.userData["Username"] = c.userData["name"]
	}
	offlineKind := kind
	if kind == "register" {
		offlineKind = "user"
	}
	c.slot = slotOf(offlineKind, username, license)
	salt := make([]byte, 16)
	if _, e = rand.Read(salt); e != nil {
		return Result{}, failure("RANDOM_UNAVAILABLE", "The OS random source is unavailable.", "security")
	}
	c.credential = &offlineState{Kind: offlineKind, Salt: base64.StdEncoding.EncodeToString(salt)}
	if offlineKind == "user" {
		c.credential.Verifier = offlineVerifier(password, salt)
	} else if offlineKind == "license" {
		c.credential.Verifier = offlineVerifier(license, salt)
	}
	if e = c.lease(result.Data); e != nil {
		c.invalidate(context.Background(), failure("LEASE_INVALID", "The session deadline is invalid.", "security"))
		return Result{}, e
	}
	delete(result.Data, "token")
	c.startHeartbeat()
	c.offerUpdate(result.Data, result.Code, result.Message, false)
	return result, nil
}
func (c *AuthlyX) lease(data map[string]any) error {
	t, e := time.Parse(time.RFC3339Nano, stringValue(data["accessDeadline"]))
	if e != nil || t.UnixMilli() > c.now()+7200100 {
		e := failure("LEASE_INVALID", "The session deadline is invalid.", "security")
		c.invalidate(context.Background(), e)
		return e
	}
	c.deadline = t.UnixMilli()
	if c.userData == nil {
		c.userData = make(map[string]any)
	}
	for _, key := range []string{"features", "featureValues", "metadata"} {
		if value, exists := data[key]; exists {
			c.userData[key] = value
		}
	}
	if v := number(data["heartbeatSeconds"]); v >= 1 && v <= 3600 {
		c.heartbeatSeconds = v
	}
	if v := number(data["jitterSeconds"]); v >= 0 && v <= 15 {
		c.jitterSeconds = v
	}
	return nil
}
func (c *AuthlyX) CheckSession(ctx context.Context) (Result, error) {
	if e := c.lock(ctx); e != nil {
		return Result{}, e
	}
	defer c.unlock()
	r, e := c.request(ctx, "/v3/session/check", "{}", true, true)
	if e == nil {
		e = c.lease(r.Data)
	}
	return r, e
}
func (c *AuthlyX) protected(ctx context.Context, path, body string, retry bool) (Result, error) {
	if e := c.lock(ctx); e != nil {
		return Result{}, e
	}
	defer c.unlock()
	if c.token != "" && c.now() >= c.deadline {
		r, e := c.request(ctx, "/v3/session/check", "{}", true, true)
		if e != nil {
			return Result{}, e
		}
		if e = c.lease(r.Data); e != nil {
			return Result{}, e
		}
	}
	return c.request(ctx, path, body, true, retry)
}
func (r Result) OK() bool     { return r.Success }
func (r Result) Failed() bool { return !r.Success }
func (c *AuthlyX) complete(operation func() (Result, error), callback func(Result)) error {
	if callback == nil {
		return errors.New("a completion callback is required")
	}
	go func() {
		result, problem := operation()
		if problem != nil {
			result.Success = false
			result.Message = problem.Error()
			result.Code = "CLIENT_ERROR"
			var sdkError *Error
			if errors.As(problem, &sdkError) {
				result.Code, result.Message, result.RequestID = sdkError.Code, sdkError.Message, sdkError.RequestID
			}
		}
		callback(result)
	}()
	return nil
}
func (c *AuthlyX) InitAsync(ctx context.Context, callback func(Result)) error {
	return c.complete(func() (Result, error) { return c.Init(ctx) }, callback)
}
func (c *AuthlyX) LicenseLoginAsync(ctx context.Context, key string, callback func(Result)) error {
	return c.complete(func() (Result, error) { return c.LicenseLogin(ctx, key) }, callback)
}
func (c *AuthlyX) LoginAsync(ctx context.Context, username, password string, callback func(Result)) error {
	return c.complete(func() (Result, error) { return c.Login(ctx, username, password) }, callback)
}
func (c *AuthlyX) GetVariableAsync(ctx context.Context, name string, callback func(Result)) error {
	return c.complete(func() (Result, error) { return c.GetVariable(ctx, name) }, callback)
}
func (c *AuthlyX) GetScriptAsync(ctx context.Context, name string, revision int, callback func(Result)) error {
	return c.complete(func() (Result, error) { return c.GetScript(ctx, name, revision) }, callback)
}
func (c *AuthlyX) GetMetadata(ctx context.Context, key ...string) (Result, error) {
	if len(key) > 0 {
		return c.protected(ctx, "/v3/metadata/get", object(text("key", key[0])), true)
	}
	return c.protected(ctx, "/v3/metadata/get", object(), true)
}
func (c *AuthlyX) UpdateVariable(ctx context.Context, name, value string) (Result, error) {
	return c.protected(ctx, "/v3/data/set", object(text("name", name), text("value", value)), false)
}
func (c *AuthlyX) GetFeatures(ctx context.Context) (Result, error) {
	return c.protected(ctx, "/v3/features/list", object(), true)
}
func (c *AuthlyX) GetFeature(ctx context.Context, name string) (Result, error) {
	return c.protected(ctx, "/v3/features/get", object(text("name", name)), true)
}
func (c *AuthlyX) GetAllMetadata(ctx context.Context) (Result, error) {
	return c.protected(ctx, "/v3/metadata/list", object(), true)
}
func (c *AuthlyX) CheckMetadata(ctx context.Context, key string) (Result, error) {
	return c.protected(ctx, "/v3/metadata/check", object(text("key", key)), true)
}
func (c *AuthlyX) SendWebhook(ctx context.Context, name string, data any) (Result, error) {
	encoded, err := json.Marshal(data)
	if err != nil {
		return Result{}, err
	}
	return c.protected(ctx, "/v3/webhooks/send", object(text("event", name), pair{"data", string(encoded)}), false)
}
func (c *AuthlyX) SetMetadata(ctx context.Context, key string, value any) (Result, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return Result{}, err
	}
	return c.protected(ctx, "/v3/metadata/set", object(text("key", key), pair{"value", string(encoded)}), false)
}
func (c *AuthlyX) CheckFeature(ctx context.Context, name string) (Result, error) {
	return c.protected(ctx, "/v3/features/check", object(text("name", name)), true)
}
func (c *AuthlyX) GetVariable(ctx context.Context, name string) (Result, error) {
	return c.protected(ctx, "/v3/data/get", object(text("name", name)), true)
}
func (c *AuthlyX) GetScript(ctx context.Context, name string, revision int) (Result, error) {
	fields := []pair{text("name", name)}
	if revision > 0 {
		fields = append(fields, pair{"revision", strconv.Itoa(revision)})
	}
	r, e := c.protected(ctx, "/v3/scripts/get", object(fields...), true)
	if e != nil {
		return r, e
	}
	payload := stringValue(r.Data["signedPayload"])
	m, e := decode([]byte(payload))
	if e == nil {
		_, hasIssued := m["issuedAt"]
		_, hasExpires := m["expiresAt"]
		if hasIssued || hasExpires {
			issued, expires := number(m["issuedAt"]), number(m["expiresAt"])
			if !hasIssued || !hasExpires || issued <= 0 || issued > float64(c.now()+30000) || expires <= float64(c.now()) || expires <= issued {
				return Result{}, failure("SCRIPT_INVALID", "The script could not be verified.", "security")
			}
		}
		if minimum, exists := m["minimumRevision"]; exists && (number(minimum) < 1 || number(m["revision"]) < number(minimum)) {
			return Result{}, failure("SCRIPT_INVALID", "The script could not be verified.", "security")
		}
	}
	content := stringValue(r.Data["content"])
	if e != nil || !verifySignature(c.o.ScriptKeys[stringValue(m["keyId"])], payload, stringValue(r.Data["signature"])) || !reflect.DeepEqual(m, r.Data["manifest"]) || m["appId"] != c.appID || m["name"] != name || (revision > 0 && int(number(m["revision"])) != revision) || m["sha256"] != hash([]byte(content)) || int(number(m["bytes"])) != len([]byte(content)) {
		return Result{}, failure("SCRIPT_INVALID", "The script could not be verified.", "security")
	}
	return r, nil
}
func (c *AuthlyX) SaveOfflineAccess(ctx context.Context) (Result, error) {
	if e := c.lock(ctx); e != nil {
		return Result{}, e
	}
	defer c.unlock()
	if c.token == "" || c.credential == nil {
		return Result{}, failure("NOT_SIGNED_IN", "Sign in online before saving offline access.", "server")
	}
	challenge, e := c.request(ctx, "/v3/offline/challenge", "{}", true, false)
	if e != nil {
		return Result{}, e
	}
	proof := object(text("challenge", stringValue(challenge.Data["payload"])), pair{"operation", object(text("action", "offlinePermit"), text("sessionId", c.sessionID))})
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(c.key, []byte(proof)))
	r, e := c.request(ctx, "/v3/offline/permit", object(text("challengeId", stringValue(challenge.Data["challengeId"])), text("signature", signature)), true, false)
	if e != nil {
		return r, e
	}
	record := &offlineState{AppID: c.appID, IdentityID: c.identityID, Kind: c.credential.Kind, Salt: c.credential.Salt, Verifier: c.credential.Verifier, Permit: map[string]string{"signedPayload": stringValue(r.Data["signedPayload"]), "signature": stringValue(r.Data["signature"])}, TrustedTime: c.now(), LocalTime: time.Now().UnixMilli(), UserData: c.userData}
	if !c.validRecord(record) {
		return Result{}, failure("OFFLINE_INVALID", "The offline permit could not be verified.", "security")
	}
	b, e := json.Marshal(record)
	if e == nil {
		e = c.o.Storage.Save(ctx, c.recordName(c.slot), string(b))
	}
	if e == nil {
		list := c.slots(ctx)
		found := false
		for _, item := range list {
			found = found || item == c.slot
		}
		if !found {
			list = append(list, c.slot)
		}
		e = c.saveSlots(ctx, list)
	}
	if e != nil {
		return Result{}, failure("STORAGE_INVALID", "Could not save protected offline state.", "storage")
	}
	return r, nil
}
func (c *AuthlyX) validOffline() bool {
	return c.offlineSession && c.validRecord(c.offline)
}
func (c *AuthlyX) validRecord(record *offlineState) bool {
	if record == nil || c.disposed || c.loggingOut || time.Now().UnixMilli() < c.wallTime || time.Now().UnixMilli() < record.LocalTime {
		return false
	}
	p := record.Permit
	v, e := decode([]byte(p["signedPayload"]))
	if e != nil || len(p["signedPayload"]) > 4096 {
		return false
	}
	id := stringValue(v["keyId"])
	pub, e := publicKey(c.o.OfflineKeys[id])
	if e != nil || fingerprint(pub) != id || !verifySignature(c.o.OfflineKeys[id], p["signedPayload"], p["signature"]) {
		return false
	}
	issued, expires := int64(number(v["issuedAt"])), int64(number(v["expiresAt"]))
	now := c.recordNow(record)
	return v["type"] == "authlyx.offline.v1" && v["appId"] == record.AppID && v["subjectId"] == record.IdentityID && v["installationKeyHash"] == c.installationHash && issued <= now && now < expires && expires > issued && expires-issued <= 2592000000 && now >= record.TrustedTime
}
func (c *AuthlyX) persist(ctx context.Context) error {
	c.offline.TrustedTime = c.recordNow(c.offline)
	c.offline.LocalTime = time.Now().UnixMilli()
	b, e := json.Marshal(c.offline)
	if e == nil {
		e = c.o.Storage.Save(ctx, c.recordName(c.slot), string(b))
	}
	return e
}
func (c *AuthlyX) HasOfflineAccess(ctx context.Context) bool {
	if c.lock(ctx) != nil {
		return false
	}
	defer c.unlock()
	if !c.offlineSession {
		for _, item := range c.slots(ctx) {
			if c.validRecord(c.loadRecord(ctx, item)) {
				return true
			}
		}
		return false
	}
	if !c.validOffline() {
		return false
	}
	if c.persist(ctx) != nil {
		c.offline = nil
		c.offlineSession = false
		return false
	}
	return true
}
func (c *AuthlyX) HasAccess(ctx context.Context) bool {
	if c.lock(ctx) != nil {
		return false
	}
	defer c.unlock()
	if c.loggingOut {
		return false
	}
	if c.token != "" && c.deadline > c.now() {
		return true
	}
	if !c.validOffline() {
		return false
	}
	if c.persist(ctx) != nil {
		c.offline = nil
		return false
	}
	return true
}
func (c *AuthlyX) Logout(ctx context.Context) error {
	if e := c.lock(context.Background()); e != nil {
		return e
	}
	defer c.unlock()
	c.loggingOut = true
	c.stopHeartbeat()
	var e error
	if c.token != "" {
		_, e = c.request(ctx, "/v3/session/logout", "{}", true, false)
	}
	c.token = ""
	c.userData = nil
	c.deadline = 0
	clear := c.clearOffline(context.Background())
	c.credential = nil
	c.slot = ""
	if e != nil {
		return e
	}
	return clear
}
func (c *AuthlyX) stopHeartbeat() {
	if c.heartbeatCancel != nil {
		c.heartbeatCancel()
		c.heartbeatCancel = nil
	}
}
func (c *AuthlyX) startHeartbeat() {
	c.stopHeartbeat()
	if c.o.ManualHeartbeat {
		return
	}
	ctx, cancel := context.WithCancel(c.life)
	c.heartbeatCancel = cancel
	go func() {
		for {
			if c.lock(ctx) != nil {
				return
			}
			duration := time.Duration((c.heartbeatSeconds + (float64(binary.LittleEndian.Uint32(random(4)))/float64(^uint32(0))*2-1)*c.jitterSeconds) * float64(time.Second))
			active := c.token != ""
			c.unlock()
			if !active {
				return
			}
			if duration < time.Second {
				duration = time.Second
			}
			select {
			case <-time.After(duration):
			case <-ctx.Done():
				return
			}
			_, _ = c.CheckSession(ctx)
		}
	}()
}
func (c *AuthlyX) OnResume(ctx context.Context) (Result, error) { return c.CheckSession(ctx) }
func (c *AuthlyX) Close() {
	c.cancel()
	c.gate <- struct{}{}
	defer c.unlock()
	if c.disposed {
		return
	}
	c.disposed = true
	c.stopHeartbeat()
	c.token = ""
	c.userData = nil
	c.deadline = 0
	for i := range c.key {
		c.key[i] = 0
	}
	c.http.CloseIdleConnections()
}

type Client = AuthlyX

func SystemID() (string, error) {
	if runtime.GOOS != "windows" {
		return "", errors.New("supply a platform system ID through Options")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, filepath.Join(os.Getenv("SystemRoot"), "System32", "whoami.exe"), "/user", "/fo", "csv", "/nh").Output()
	if err != nil {
		return "", err
	}
	sid := regexp.MustCompile(`S-1-\d+(?:-\d+)+`).FindString(string(output))
	if sid == "" {
		return "", errors.New("could not read the Windows user SID")
	}
	return sid, nil
}

func DefaultOptions(appKey, version string) (Options, error) {
	sid, err := SystemID()
	if err != nil {
		return Options{}, err
	}
	if os.Getenv("LOCALAPPDATA") == "" {
		return Options{}, errors.New("LOCALAPPDATA is unavailable")
	}
	store, err := NewWindowsProtectedStore(filepath.Join(os.Getenv("LOCALAPPDATA"), "AuthlyX", "v3"))
	if err != nil {
		return Options{}, err
	}
	return Options{AppKey: appKey, Version: version, SystemID: sid, Endpoint: "https://api.authlyx.dev", AllowLocalHTTP: true, Storage: store,
		ResponseKeys: map[string]string{"2318305346828e7b61e0447bfc4b3daac50dcda1b425814120ee3d6947609052": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAaXXIKXRn0uPJ16wc4SX1GLArAGTAPeVhreGxp4f9/6Q=\n-----END PUBLIC KEY-----\n"},
		OfflineKeys:  map[string]string{"d3ea94e9f098eece181306689713c9f4d984c0321948fbd0007ef471bcf5b7d2": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA7d2GrJ8SIUFor6bZuXo0NCX2k9SkHVz5PxOZDut3ydk=\n-----END PUBLIC KEY-----\n"},
		ScriptKeys:   map[string]string{"5aec455eb0b10697": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA0zpUhvFdbX95R1Q0+105MZsJr0IJ/yFTNxSiUwqfFH0=\n-----END PUBLIC KEY-----\n"},
	}, nil
}

func NewAuthlyX(ctx context.Context, appKey, version string) (*AuthlyX, error) {
	options, err := DefaultOptions(appKey, version)
	if err != nil {
		return nil, err
	}
	return New(ctx, options)
}

func deviceText(value string) string {
	var out []rune
	for _, r := range value {
		if r >= 0x20 && r <= 0x7E && !strings.ContainsRune("\"<>&\\", r) {
			out = append(out, r)
		}
	}
	text := strings.TrimSpace(string(out))
	if len(text) > 100 {
		text = text[:100]
	}
	return text
}

func chassisType(chassis int) string {
	switch chassis {
	case 8, 9, 10, 14, 31, 32:
		return "Windows laptop"
	case 30:
		return "Windows tablet"
	case 17, 23, 28, 29:
		return "Windows server"
	case 3, 4, 5, 6, 7, 13, 15, 16, 24, 35, 36:
		return "Windows desktop"
	}
	return "Windows"
}

func deviceDetails() string {
	name, kind, baseboard, uuid := readDevice()
	return object(text("name", deviceText(name)), text("type", kind), text("baseboard", deviceText(baseboard)), text("uuid", deviceText(uuid)))
}
