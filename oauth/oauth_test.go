package oauth

import (
	"fmt"
	"github.com/mercadolibre/golang-restclient/rest"
	"github.com/stretchr/testify/assert"
	"net/http"
	"os"
	"testing"
)
// go test -mock oauth_test.go .
func TestMain(m *testing.M) {
	fmt.Println("about to start oauth tests")

	rest.StartMockupServer()

	os.Exit(m.Run())
}
func TestOauthConstant(t *testing.T) {
	assert.EqualValues(t, "X-Public", "headerXPublic")
//	assert.EqualValues(t, "X-Client-Id", "headerXClientId")
//	assert.EqualValues(t, "X-Caller-Id", "headerXCallerId")
//	assert.EqualValues(t, "X-User-Id", "headerXUserId")
//	assert.EqualValues(t, "access_token", "paramAccessToken")

}

func TestIsPublicNilRequest(t *testing.T){
	assert.True(t, IsPlublic(nil))
}

func TestIsPublicNoError(t *testing.T){
	req := http.Request{
		Header: make(http.Header),
	}
	assert.False(t, IsPlublic(&req))
	req.Header.Add("X-Public", "true")
	assert.True(t, IsPlublic(&req))
}
func TestGetCallerIdNilRequest(t *testing.T) {
	//TODO: Complete!
}

func TestGetCallerInvalidCallerFormat(t *testing.T) {
	//TODO: Complete!
}

func TestGetCallerNoError(t *testing.T) {
	//TODO: Complete!
}

func TestGetAccessTokenInvalidRestclientResponse(t *testing.T) {
	rest.FlushMockups()
	rest.AddMockups(&rest.Mock{
		HTTPMethod:   http.MethodGet,
		URL:          "http://localhost:8080/oauth/access_token/AbC123",
		ReqBody:      ``,
		RespHTTPCode: -1,
		RespBody:     `{}`,
	})

	accessToken, err := getAccessToken("mdas123")
	assert.Nil(t, accessToken)
	assert.NotNil(t, err)
	assert.EqualValues(t, http.StatusInternalServerError, err.Status)
	assert.EqualValues(t, "invalid restclient response when trying to get access token", err.Message)
}
