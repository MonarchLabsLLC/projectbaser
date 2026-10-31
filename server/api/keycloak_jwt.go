package api

import (
	"context"
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	keycloakClockSkew        = 60 * time.Second
	keycloakJWKSMaxAge       = time.Hour
	keycloakJWKSMinRefresh   = 10 * time.Second
	keycloakMinRSAKeyBits    = 2048
	keycloakMaxTokenBytes    = 16 << 10
	keycloakMaxJWKSBodyBytes = 1 << 20
)

var (
	errKeycloakNotConfigured = errors.New("keycloak is not configured")
	errKeycloakTokenInvalid  = errors.New("invalid token")
)

var keycloakSigningAlgs = map[string]struct {
	hash crypto.Hash
	pss  bool
}{
	"RS256": {crypto.SHA256, false},
	"RS384": {crypto.SHA384, false},
	"RS512": {crypto.SHA512, false},
	"PS256": {crypto.SHA256, true},
	"PS384": {crypto.SHA384, true},
	"PS512": {crypto.SHA512, true},
}

type keycloakAudience []string

func (a *keycloakAudience) UnmarshalJSON(data []byte) error {
	var one string
	if err := json.Unmarshal(data, &one); err == nil {
		*a = keycloakAudience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

type keycloakJWTVerifier struct {
	issuer   string
	clientID string
	jwksURL  string
	client   *http.Client
	now      func() time.Time

	mu          sync.Mutex
	keys        map[string]*rsa.PublicKey
	fetchedAt   time.Time
	lastAttempt time.Time
}

func newKeycloakJWTVerifier(issuer, clientID, jwksURL string, client *http.Client) *keycloakJWTVerifier {
	return &keycloakJWTVerifier{
		issuer:   issuer,
		clientID: clientID,
		jwksURL:  jwksURL,
		client:   client,
		now:      time.Now,
	}
}

var (
	keycloakVerifiersMu sync.Mutex
	keycloakVerifiers   = map[string]*keycloakJWTVerifier{}
	keycloakJWKSClient  = &http.Client{Timeout: 5 * time.Second}
)

// keycloakVerifierFor returns the shared verifier for the configured realm and client.
func keycloakVerifierFor(baseURL, realm, clientID string) (*keycloakJWTVerifier, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	realm = strings.TrimSpace(realm)
	clientID = strings.TrimSpace(clientID)
	if baseURL == "" || realm == "" || clientID == "" {
		return nil, errKeycloakNotConfigured
	}
	issuer := baseURL + "/realms/" + url.PathEscape(realm)
	cacheKey := issuer + "\x00" + clientID

	keycloakVerifiersMu.Lock()
	defer keycloakVerifiersMu.Unlock()
	if v, ok := keycloakVerifiers[cacheKey]; ok {
		return v, nil
	}
	v := newKeycloakJWTVerifier(issuer, clientID, issuer+"/protocol/openid-connect/certs", keycloakJWKSClient)
	keycloakVerifiers[cacheKey] = v
	return v, nil
}

type keycloakJWTHeader struct {
	Alg  string          `json:"alg"`
	Kid  string          `json:"kid"`
	Crit json.RawMessage `json:"crit"`
}

// Verify checks the token signature against the realm keys and validates the
// issuer, audience, token type and lifetime before returning its claims.
func (v *keycloakJWTVerifier) Verify(ctx context.Context, token string) (*KeycloakTokenClaims, error) {
	if len(token) == 0 || len(token) > keycloakMaxTokenBytes {
		return nil, fmt.Errorf("%w: unexpected size", errKeycloakTokenInvalid)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, fmt.Errorf("%w: malformed", errKeycloakTokenInvalid)
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: header encoding", errKeycloakTokenInvalid)
	}
	var header keycloakJWTHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("%w: header", errKeycloakTokenInvalid)
	}
	alg, ok := keycloakSigningAlgs[header.Alg]
	if !ok {
		return nil, fmt.Errorf("%w: algorithm not allowed", errKeycloakTokenInvalid)
	}
	if len(header.Crit) > 0 {
		return nil, fmt.Errorf("%w: unsupported critical header", errKeycloakTokenInvalid)
	}
	if header.Kid == "" {
		return nil, fmt.Errorf("%w: missing key id", errKeycloakTokenInvalid)
	}

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: signature encoding", errKeycloakTokenInvalid)
	}

	key, err := v.key(ctx, header.Kid)
	if err != nil {
		return nil, err
	}

	hasher := alg.hash.New()
	hasher.Write([]byte(parts[0] + "." + parts[1]))
	digest := hasher.Sum(nil)
	if alg.pss {
		err = rsa.VerifyPSS(key, alg.hash, digest, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	} else {
		err = rsa.VerifyPKCS1v15(key, alg.hash, digest, signature)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: signature", errKeycloakTokenInvalid)
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: payload encoding", errKeycloakTokenInvalid)
	}
	var claims KeycloakTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("%w: payload", errKeycloakTokenInvalid)
	}
	if err := v.validateClaims(&claims); err != nil {
		return nil, err
	}
	return &claims, nil
}

func (v *keycloakJWTVerifier) validateClaims(claims *KeycloakTokenClaims) error {
	if claims.Issuer != v.issuer {
		return fmt.Errorf("%w: issuer", errKeycloakTokenInvalid)
	}
	if claims.AuthorizedParty != v.clientID && !claims.Audience.contains(v.clientID) {
		return fmt.Errorf("%w: audience", errKeycloakTokenInvalid)
	}
	if claims.Type != "" && !strings.EqualFold(claims.Type, "Bearer") {
		return fmt.Errorf("%w: token type", errKeycloakTokenInvalid)
	}

	now := v.now()
	if claims.ExpiresAt == nil {
		return fmt.Errorf("%w: missing expiry", errKeycloakTokenInvalid)
	}
	if now.After(unixSeconds(*claims.ExpiresAt).Add(keycloakClockSkew)) {
		return fmt.Errorf("%w: expired", errKeycloakTokenInvalid)
	}
	if claims.NotBefore != nil && now.Add(keycloakClockSkew).Before(unixSeconds(*claims.NotBefore)) {
		return fmt.Errorf("%w: not yet valid", errKeycloakTokenInvalid)
	}
	if claims.IssuedAt != nil && now.Add(keycloakClockSkew).Before(unixSeconds(*claims.IssuedAt)) {
		return fmt.Errorf("%w: issued in the future", errKeycloakTokenInvalid)
	}
	return nil
}

func (a keycloakAudience) contains(value string) bool {
	for _, aud := range a {
		if aud == value {
			return true
		}
	}
	return false
}

func unixSeconds(value float64) time.Time {
	return time.Unix(int64(value), 0)
}

// key returns the realm key for kid, refreshing the JWKS when the cache is
// stale or the kid is unknown (rate limited so bad tokens cannot flood Keycloak).
func (v *keycloakJWTVerifier) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	now := v.now()
	stale := v.keys == nil || now.Sub(v.fetchedAt) > keycloakJWKSMaxAge
	if key, ok := v.keys[kid]; ok && !stale {
		return key, nil
	}
	if v.lastAttempt.IsZero() || now.Sub(v.lastAttempt) >= keycloakJWKSMinRefresh {
		v.lastAttempt = now
		keys, err := v.fetchKeys(ctx)
		if err == nil {
			v.keys = keys
			v.fetchedAt = now
		} else if v.keys == nil {
			return nil, fmt.Errorf("fetch keycloak signing keys: %w", err)
		}
	}
	if v.keys == nil {
		return nil, errors.New("keycloak signing keys are unavailable")
	}
	if key, ok := v.keys[kid]; ok {
		return key, nil
	}
	return nil, fmt.Errorf("%w: unknown key id", errKeycloakTokenInvalid)
}

type keycloakJWK struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func (v *keycloakJWTVerifier) fetchKeys(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := v.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks returned status %d", resp.StatusCode)
	}
	var set struct {
		Keys []keycloakJWK `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, keycloakMaxJWKSBodyBytes)).Decode(&set); err != nil {
		return nil, err
	}

	keys := map[string]*rsa.PublicKey{}
	for _, jwk := range set.Keys {
		if jwk.Kty != "RSA" || jwk.Kid == "" || (jwk.Use != "" && jwk.Use != "sig") {
			continue
		}
		key, err := parseRSAJWK(jwk)
		if err != nil {
			continue
		}
		keys[jwk.Kid] = key
	}
	if len(keys) == 0 {
		return nil, errors.New("jwks contains no usable RSA signing keys")
	}
	return keys, nil
}

func parseRSAJWK(jwk keycloakJWK) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, err
	}
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)
	if n.BitLen() < keycloakMinRSAKeyBits || !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1 {
		return nil, errors.New("unsupported rsa key")
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}
