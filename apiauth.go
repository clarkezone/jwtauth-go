package jwtauth

import (
	"fmt"
	jwt "github.com/dgrijalva/jwt-go"
	"net/http"
)

type ApiSecurity struct {
	currentProvider userProvider
	currentAuth     authProvider
}

type userProvider interface {
	Login(username string, password string) (result bool, userid string)
}

type authProvider interface {
	GenerateToken(userid string) (token string, err error)
}

func (a *ApiSecurity) RegisterLoginHandlers() {
	http.HandleFunc("/login", a.Login)
}

func CreateApiSecurity(p userProvider) (instance *ApiSecurity) {
	r := new(ApiSecurity)
	r.currentProvider = p

	a := new(JwtAuthProvider)
	r.currentAuth = a

	return r
}

func (a *ApiSecurity) Login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	err := r.ParseForm()
	if err != nil {
		fmt.Printf("error parsing form\n")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	username := r.PostFormValue("username")
	password := r.PostFormValue("password")

	fmt.Printf("username:%v password:%v\n", username, password)

	if username == "" || password == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	success, userid := a.currentProvider.Login(username, password)

	if success {
		token, err := a.currentAuth.GenerateToken(userid)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
		} else {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"t":"%s"}`, token)
		}
	} else {
		w.WriteHeader(http.StatusUnauthorized)
	}
}

func UserFromToken(tokstring string) (id string) {
	token, err := jwt.Parse(tokstring, func(t *jwt.Token) (interface{}, error) {
		return privateKey, nil
	})
	if err == nil && token.Valid {
		return token.Claims["ID"].(string)
	}
	return ""

}
