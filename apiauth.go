package jwtauth

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
)

type ApiSecurity struct {
	currentProvider userProvider
	currentAuth     authProvider
}

type userProvider interface {
	Login(username string, password string) (result bool, userid string)
	GetRoles(userid string) []int
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
		claims := token.Claims.(jwt.MapClaims)
		return claims["ID"].(string)
	}
	return ""

}

func IsInRole(roleid int, r *http.Request) bool {
	//fmt.Printf("IsInRole:roleid %v\n", roleid)
	hd := r.Header.Get("roles")
	//fmt.Printf("IsInRole:header %v\n", hd)
	roleString := strings.Split(hd, ",")
	//fmt.Printf("IsInRole:fromheader %v\n", roleString)
	for _, i := range roleString {
		//fmt.Printf("i=%v\n", i)
		role, err := strconv.Atoi(i)
		if err == nil {
			//fmt.Printf("IsInRole:compare %v %v\n", role, roleid)
			if role == roleid {
				//fmt.Printf("IsInRole:match\n")
				return true
			}
		}
	}

	//fmt.Printf("IsInRole:nomatch\n")
	return false
}
