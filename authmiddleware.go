package jwtauth

import (
	"fmt"
	"net/http"

	jwt "github.com/dgrijalva/jwt-go"
)

func (a *ApiSecurity) RequireTokenAuthentication(fn http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		token, err := jwt.ParseFromRequest(
			r,
			func(token *jwt.Token) (interface{}, error) {
				return privateKey, nil
			})

		if err == nil && token.Valid {
			roles := a.currentProvider.GetRoles(token.Claims["ID"].(string))
			var rolesHeader string
			for _, i := range roles {
				rolesHeader += fmt.Sprintf("%v,", i)
			}
			r.Header.Add("userid", token.Claims["ID"].(string))
			r.Header.Add("roles", rolesHeader)
			fn(rw, r)
		} else {
			rw.WriteHeader(http.StatusUnauthorized)
		}
	}
}

func (a *ApiSecurity) CorsOptions(fn http.HandlerFunc) http.HandlerFunc {
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
