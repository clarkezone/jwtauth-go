package jwtauth

import (
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

func SecureTestMethod(wr http.ResponseWriter, r *http.Request) {
	userid := r.Header.Get("userid")
	fmt.Fprintln(wr, "Tweets")
	fmt.Printf("userid:" + userid)
}

func TestLogin(t *testing.T) {
	var provider = dummyUserProvider{}

	api := CreateApiSecurity(provider)

	ts := httptest.NewServer(http.HandlerFunc(api.Login))

	res, err := http.PostForm(ts.URL, url.Values{"username": {"testuser"}, "password": {"testpassword"}})
	if err != nil {
		log.Fatal(err)
	}

	if res.StatusCode != http.StatusOK {
		t.Fail()
	}

	result := GetBody(res)

	user := UserFromToken(result)
	if user != "abc123" {
		t.Fail()
	}
}

func TestSecureRequest(t *testing.T) {
	var currentAuth JwtAuthProvider

	userid := "abc123"
	token, _ := currentAuth.GenerateToken(userid)

	ts := httptest.NewServer(http.HandlerFunc(RequireTokenAuthentication(SecureTestMethod)))

	client := &http.Client{}

	req, _ := http.NewRequest("GET", ts.URL, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	result, _ := client.Do(req)
	if result.StatusCode != http.StatusOK {
		t.Fail()
	}
}

func GetBody(res *http.Response) (result string) {
	response, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		log.Fatal(err)
	}
	return string(response)
}
