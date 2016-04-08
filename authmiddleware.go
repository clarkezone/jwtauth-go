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

func CorsOptions(fn http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			rw.Header().Set("Access-Control-Allow-Headers", "accepts, authorization, content-type, x-api-applicationid, access-control-allow-origin")
			rw.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
			rw.Header().Set("Access-Control-Allow-Origin", "*")
			rw.WriteHeader(http.StatusOK)
			// Do not run the passed in function in this branch as we don't want to continuing the hander pipeline
			return
		} else {
			rw.Header().Set("Access-Control-Allow-Origin", "*")
			fn(rw, r)
		}
	}

}
