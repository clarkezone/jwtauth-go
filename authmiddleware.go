package jwtauth

import (
	"fmt"
	"net/http"

	jwt "github.com/dgrijalva/jwt-go"
	request "github.com/dgrijalva/jwt-go/request"
)

func (a *ApiSecurity) RequireTokenAuthentication(fn http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		//token, err := jwt.ParseFromRequest(
		token, err := request.ParseFromRequest(
			r,
			request.OAuth2Extractor,
			func(token *jwt.Token) (interface{}, error) {
				return privateKey, nil
			})

		if err == nil && token.Valid {
			roles := a.currentProvider.GetRoles(token.Claims.(jwt.MapClaims)["ID"].(string))
			var rolesHeader string
			for _, i := range roles {
				rolesHeader += fmt.Sprintf("%v,", i)
			}
			r.Header.Add("userid", token.Claims.(jwt.MapClaims)["ID"].(string))
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
