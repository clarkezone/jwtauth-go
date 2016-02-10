package jwtauth

import (
	jwt "github.com/dgrijalva/jwt-go"
	"time"
)

type JwtAuthProvider struct {
}

var (
	privateKey []byte
)

func init() {
	//Replace this with a better key
	privateKey = []byte("randomprivatekeyseed")
}

func (p *JwtAuthProvider) GenerateToken(userid string) (token string, err error) {
	t := jwt.New(jwt.GetSigningMethod("HS256"))
	// need correct fields
	t.Claims["ID"] = userid
	t.Claims["EXP"] = time.Now().Add(time.Minute * 5).Unix()

	tokenString, err := t.SignedString(privateKey)

	return tokenString, err
}
