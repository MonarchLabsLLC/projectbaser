package api

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testIssuer   = "https://auth.example.test/auth/realms/test-realm"
	testClientID = "app-projectbaser"
	testKid      = "kid-1"
)

type testRealm struct {
	t       *testing.T
	key     *rsa.PrivateKey
	kid     string
	server  *httptest.Server
	fetches atomic.Int32
	now     time.Time
}

func newTestRealm(t *testing.T) *testRealm {
	t.Helper()
	realm := &testRealm{t: t, key: mustRSAKey(t), kid: testKid, now: time.Unix(1_800_000_000, 0)}
	realm.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		realm.fetches.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"keys": []map[string]string{{
			"kid": realm.kid, "kty": "RSA", "use": "sig", "alg": "RS256",
			"n": b64(realm.key.PublicKey.N.Bytes()),
			"e": b64(big.NewInt(int64(realm.key.PublicKey.E)).Bytes()),
		}}})
	}))
	t.Cleanup(realm.server.Close)
	return realm
}

func (r *testRealm) verifier() *keycloakJWTVerifier {
	v := newKeycloakJWTVerifier(testIssuer, testClientID, r.server.URL, r.server.Client())
	v.now = func() time.Time { return r.now }
	return v
}

func (r *testRealm) claims() map[string]interface{} {
	return map[string]interface{}{
		"iss":   testIssuer,
		"aud":   "account",
		"azp":   testClientID,
		"typ":   "Bearer",
		"sub":   "sub-1",
		"email": "member@example.test",
		"iat":   r.now.Unix() - 10,
		"exp":   r.now.Unix() + 300,
		"realm_access": map[string]interface{}{
			"roles": []string{requiredKeycloakRole},
		},
	}
}

func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func b64(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }

func encodeSegment(t *testing.T, value interface{}) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return b64(data)
}

func signRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]interface{}) string {
	t.Helper()
	signingInput := encodeSegment(t, map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid}) + "." + encodeSegment(t, claims)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + b64(signature)
}

func TestKeycloakJWTVerifierAcceptsSignedToken(t *testing.T) {
	realm := newTestRealm(t)
	claims, err := realm.verifier().Verify(context.Background(), signRS256(t, realm.key, realm.kid, realm.claims()))
	if err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if claims.Sub != "sub-1" || claims.Email != "member@example.test" || !(&API{}).hasRequiredRole(claims, requiredKeycloakRole) {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestKeycloakJWTVerifierAcceptsAudienceListWithoutAzp(t *testing.T) {
	realm := newTestRealm(t)
	c := realm.claims()
	delete(c, "azp")
	c["aud"] = []string{"account", testClientID}
	if _, err := realm.verifier().Verify(context.Background(), signRS256(t, realm.key, realm.kid, c)); err != nil {
		t.Fatalf("token with the client in aud rejected: %v", err)
	}
}

func TestKeycloakJWTVerifierRejectsInvalidTokens(t *testing.T) {
	realm := newTestRealm(t)
	signingInputFor := func(header map[string]string, claims map[string]interface{}) string {
		return encodeSegment(t, header) + "." + encodeSegment(t, claims)
	}

	unsigned := signingInputFor(map[string]string{"alg": "none", "kid": testKid}, realm.claims()) + "."
	noneWithJunk := signingInputFor(map[string]string{"alg": "none", "kid": testKid}, realm.claims()) + ".c2ln"

	hsInput := signingInputFor(map[string]string{"alg": "HS256", "kid": testKid}, realm.claims())
	mac := hmac.New(sha256.New, realm.key.PublicKey.N.Bytes())
	mac.Write([]byte(hsInput))
	hmacToken := hsInput + "." + b64(mac.Sum(nil))

	otherKeySameKid := signRS256(t, mustRSAKey(t), testKid, realm.claims())

	valid := signRS256(t, realm.key, realm.kid, realm.claims())
	tamperedClaims := realm.claims()
	tamperedClaims["sub"] = "someone-else"
	tampered := encodeSegment(t, map[string]string{"alg": "RS256", "kid": testKid}) + "." +
		encodeSegment(t, tamperedClaims) + valid[strings.LastIndex(valid, "."):]

	withClaim := func(key string, value interface{}) string {
		c := realm.claims()
		if value == nil {
			delete(c, key)
		} else {
			c[key] = value
		}
		return signRS256(t, realm.key, realm.kid, c)
	}
	wrongAudience := func() string {
		c := realm.claims()
		c["azp"] = "app-pipeleads"
		c["aud"] = []string{"account", "app-pipeleads"}
		return signRS256(t, realm.key, realm.kid, c)
	}()

	cases := map[string]string{
		"empty":                   "",
		"not a jwt":               "abc",
		"unsigned alg none":       unsigned,
		"alg none with signature": noneWithJunk,
		"hmac alg confusion":      hmacToken,
		"signed by a foreign key": otherKeySameKid,
		"tampered payload":        tampered,
		"unknown key id":          signRS256(t, realm.key, "kid-unknown", realm.claims()),
		"wrong issuer":            withClaim("iss", "https://evil.example.test/auth/realms/test-realm"),
		"missing issuer":          withClaim("iss", nil),
		"wrong audience":          wrongAudience,
		"expired":                 withClaim("exp", realm.now.Unix()-120),
		"missing expiry":          withClaim("exp", nil),
		"not yet valid":           withClaim("nbf", realm.now.Unix()+600),
		"issued in the future":    withClaim("iat", realm.now.Unix()+600),
		"refresh token type":      withClaim("typ", "Refresh"),
		"padded base64 segments":  valid + "=",
		"extra segment":           valid + ".x",
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			claims, err := realm.verifier().Verify(context.Background(), token)
			if err == nil {
				t.Fatalf("token accepted: %+v", claims)
			}
			t.Logf("rejected: %v", err)
		})
	}
}

func TestKeycloakJWTVerifierAllowsClockSkew(t *testing.T) {
	realm := newTestRealm(t)
	c := realm.claims()
	c["exp"] = realm.now.Unix() - 30
	c["nbf"] = realm.now.Unix() + 30
	if _, err := realm.verifier().Verify(context.Background(), signRS256(t, realm.key, realm.kid, c)); err != nil {
		t.Fatalf("token within clock skew rejected: %v", err)
	}
}

func TestKeycloakJWTVerifierCachesAndRefreshesOnKeyRotation(t *testing.T) {
	realm := newTestRealm(t)
	v := realm.verifier()
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if _, err := v.Verify(ctx, signRS256(t, realm.key, realm.kid, realm.claims())); err != nil {
			t.Fatal(err)
		}
	}
	if got := realm.fetches.Load(); got != 1 {
		t.Fatalf("JWKS fetched %d times, want 1 (cached)", got)
	}

	realm.key, realm.kid = mustRSAKey(t), "kid-2"
	rotated := signRS256(t, realm.key, realm.kid, realm.claims())
	if _, err := v.Verify(ctx, rotated); err == nil {
		t.Fatal("unknown kid must not trigger an immediate second fetch inside the refresh window")
	}

	realm.now = realm.now.Add(keycloakJWKSMinRefresh)
	if _, err := v.Verify(ctx, signRS256(t, realm.key, realm.kid, realm.claims())); err != nil {
		t.Fatalf("rotated key not picked up after refresh: %v", err)
	}
	if got := realm.fetches.Load(); got != 2 {
		t.Fatalf("JWKS fetched %d times, want 2", got)
	}
}

func TestKeycloakJWTVerifierFailsClosedWhenKeysUnavailable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	realm := newTestRealm(t)
	v := newKeycloakJWTVerifier(testIssuer, testClientID, server.URL, server.Client())
	v.now = func() time.Time { return realm.now }
	if _, err := v.Verify(context.Background(), signRS256(t, realm.key, realm.kid, realm.claims())); err == nil {
		t.Fatal("token accepted without signing keys")
	}
}

func TestKeycloakVerifierForRequiresConfiguration(t *testing.T) {
	for _, cfg := range [][3]string{
		{"", "realm", "client"},
		{"https://auth.example.test/auth", "", "client"},
		{"https://auth.example.test/auth", "realm", ""},
	} {
		if _, err := keycloakVerifierFor(cfg[0], cfg[1], cfg[2]); !errors.Is(err, errKeycloakNotConfigured) {
			t.Fatalf("keycloakVerifierFor(%q) err = %v, want not configured", cfg, err)
		}
	}

	v, err := keycloakVerifierFor("https://auth.example.test/auth/", "test-realm", testClientID)
	if err != nil {
		t.Fatal(err)
	}
	if v.issuer != testIssuer || v.jwksURL != testIssuer+"/protocol/openid-connect/certs" {
		t.Fatalf("issuer=%q jwks=%q", v.issuer, v.jwksURL)
	}
	again, _ := keycloakVerifierFor("https://auth.example.test/auth", "test-realm", testClientID)
	if again != v {
		t.Fatal("verifier (and its key cache) should be shared per realm and client")
	}
}
