package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	Sub  string `json:"sub"`
	Role string `json:"role"`
	jwt.RegisteredClaims
}

var ErrInvalidToken = errors.New("invalid token")

func Issue(secret, issuer, sub, role string, ttl time.Duration) (string, *Claims, error) {
	now := time.Now()
	claims := &Claims{
		Sub:  sub,
		Role: role,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   sub,
			Issuer:    issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(secret))
	if err != nil {
		return "", nil, err
	}
	return signed, claims, nil
}

func Verify(tokenStr, secret string) (*Claims, error) {
	tok, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil || !tok.Valid {
		return nil, ErrInvalidToken
	}
	claims, ok := tok.Claims.(*Claims)
	if !ok {
		return nil, ErrInvalidToken
	}
	return claims, nil
}

var roleRank = map[string]int{
	"viewer":    1,
	"author":    2,
	"moderator": 3,
	"admin":     4,
}

func HasRole(role, required string) bool {
	return roleRank[role] >= roleRank[required]
}
