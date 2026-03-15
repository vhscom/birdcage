package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/text/unicode/norm"
)

const (
	pbkdf2Iterations = 210_000
	saltBytes        = 16
	accessExpiry     = 15 * time.Minute
	refreshExpiry    = 7 * 24 * time.Hour
)

// --- Password hashing (PBKDF2-SHA384, NIST SP 800-132) ---

// hashPassword returns "$pbkdf2-sha384$v1$210000$salt$hash$digest".
func hashPassword(password string) (string, error) {
	password = normalizePassword(password)
	salt := make([]byte, saltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := pbkdf2.Key([]byte(password), salt, pbkdf2Iterations, 48, sha512.New384)
	digest := sha384(hash)
	return fmt.Sprintf("$pbkdf2-sha384$v1$%d$%s$%s$%s",
		pbkdf2Iterations,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
		base64.RawStdEncoding.EncodeToString(digest),
	), nil
}

// verifyPassword checks a password against a stored hash using constant-time comparison.
func verifyPassword(password, stored string) bool {
	password = normalizePassword(password)
	parts := strings.Split(stored, "$")
	if len(parts) != 7 { // ["", "pbkdf2-sha384", "v1", iters, salt, hash, digest]
		return false
	}
	salt, _ := base64.RawStdEncoding.DecodeString(parts[4])
	storedHash, _ := base64.RawStdEncoding.DecodeString(parts[5])
	storedDigest, _ := base64.RawStdEncoding.DecodeString(parts[6])
	if len(salt) == 0 || len(storedHash) == 0 || len(storedDigest) == 0 {
		return false
	}
	derived := pbkdf2.Key([]byte(password), salt, pbkdf2Iterations, 48, sha512.New384)
	derivedDigest := sha384(derived)
	h := hmac.Equal(derived, storedHash)
	d := hmac.Equal(derivedDigest, storedDigest)
	return h && d
}

// rejectConstantTime prevents timing-based user enumeration by performing
// a full PBKDF2 verification against dummy data when the user doesn't exist.
func rejectConstantTime(password string) {
	dummy := "$pbkdf2-sha384$v1$210000$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	verifyPassword(password, dummy)
}

func sha384(data []byte) []byte {
	h := sha512.New384()
	h.Write(data)
	return h.Sum(nil)
}

func normalizePassword(p string) string {
	p = norm.NFKC.String(p)
	return strings.Join(strings.Fields(p), " ")
}

// --- JWT ---

type TokenClaims struct {
	UID int    `json:"uid"`
	SID string `json:"sid"`
	Typ string `json:"typ"`
	Gen int    `json:"gen"`
	jwt.RegisteredClaims
}

func signToken(uid int, sid, typ, secret string, expiry time.Duration) (string, error) {
	now := timeNow()
	claims := TokenClaims{
		UID: uid,
		SID: sid,
		Typ: typ,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(expiry)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
}

func signRefreshToken(uid int, sid, secret string, gen int) (string, error) {
	now := timeNow()
	claims := TokenClaims{
		UID: uid, SID: sid, Typ: "refresh", Gen: gen,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(refreshExpiry)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
}

func verifyToken(raw, secret, expectedTyp string) (*TokenClaims, error) {
	token, err := jwt.ParseWithClaims(raw, &TokenClaims{}, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected alg %v", t.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}
	c, ok := token.Claims.(*TokenClaims)
	if !ok || !token.Valid || c.Typ != expectedTyp {
		return nil, fmt.Errorf("invalid token")
	}
	return c, nil
}

// --- Utility ---

func hashAPIKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return fmt.Sprintf("%x", h)
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func hmacSHA256(key, data string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(data))
	return fmt.Sprintf("%x", mac.Sum(nil))
}

func sha256Digest(data []byte) [32]byte {
	return sha256.Sum256(data)
}
