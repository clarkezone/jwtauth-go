package jwtauth

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

type dummyUserProvider struct {
}

func (a dummyUserProvider) Login(username string, password string) (result bool, userid string) {
	if username == "testuser" && password == "testpassword" {
		return true, "abc123"
	}
	return false, ""
}

func (a dummyUserProvider) GetRoles(userid string) []int {
	return []int{3, 4, 5}
}

func SecureTestMethod(wr http.ResponseWriter, r *http.Request) {
	userid := r.Header.Get("userid")
	fmt.Fprintln(wr, "Tweets")
	fmt.Printf("userid:" + userid)
}

func createServer() (response *http.Response, security *ApiSecurity) {

	var provider = dummyUserProvider{}

	api := CreateApiSecurity(provider)

	ts := httptest.NewServer(http.HandlerFunc(api.Login))

	res, err := http.PostForm(ts.URL, url.Values{"username": {"testuser"}, "password": {"testpassword"}})
	if err != nil {
		log.Fatal(err)
	}

	return res, api
}

func TestLogin(t *testing.T) {
	res, _ := createServer()
	result := GetBody(res)

	type token struct {
		T string
	}

	var theToken token

	json.Unmarshal(result, &theToken)

	user := UserFromToken(theToken.T)
	if user != "abc123" {
		t.Fail()
	}
}

func verify(wr http.ResponseWriter, r *http.Request) {
	roles := r.Header.Get("Roles")
	if roles != "3,4,5," {
		log.Fatal("Bad roles:" + roles)
	}

	correct := IsInRole(4, r)
	if correct != true {
		log.Fatal("user should be in role 4")
	}

	incorrect := IsInRole(2, r)
	if incorrect != false {
		log.Fatal("user should not be in role 2")
	}
}

func TestRoles(t *testing.T) {
	var provider = dummyUserProvider{}

	api := CreateApiSecurity(provider)

	var currentAuth JwtAuthProvider
	userid := "abc123"
	token, _ := currentAuth.GenerateToken(userid)

	ts := httptest.NewServer(http.HandlerFunc(api.RequireTokenAuthentication(verify)))

	client := &http.Client{}

	req, _ := http.NewRequest("GET", ts.URL, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	client.Do(req)
	//verify will throw if roles are bad
}

func TestSecureRequest(t *testing.T) {

	var provider = dummyUserProvider{}

	api := CreateApiSecurity(provider)

	var currentAuth JwtAuthProvider
	userid := "abc123"
	token, _ := currentAuth.GenerateToken(userid)

	ts := httptest.NewServer(http.HandlerFunc(api.RequireTokenAuthentication(SecureTestMethod)))

	client := &http.Client{}

	req, _ := http.NewRequest("GET", ts.URL, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	result, _ := client.Do(req)
	if result.StatusCode != http.StatusOK {
		t.Fail()
	}
}

func GetBody(res *http.Response) (result []byte) {
	response, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		log.Fatal(err)
	}
	return response
}
