package jwtauth

import (
	jwt "github.com/dgrijalva/jwt-go"
	"net/http"
)

func RequireTokenAuthentication(fn http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		token, err := jwt.ParseFromRequest(
			r,
			func(token *jwt.Token) (interface{}, error) {
				return privateKey, nil
			})

		if err == nil && token.Valid {
			r.Header.Add("userid", token.Claims["ID"].(string))
			fn(rw, r)
		} else {
			rw.WriteHeader(http.StatusUnauthorized)
		}
	}
}
