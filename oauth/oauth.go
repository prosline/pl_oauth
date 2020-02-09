package oauth

import (
	"encoding/json"
	"fmt"
	"github.com/prosline/pl_util/utils/errors"
	"github.com/mercadolibre/golang-restclient/rest"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type oauthClient struct{}

type oauthInterface interface {
}
type accessToken struct{
	Id string `json:"id"`
	UserId int64 `json:"user_id"`
	ClientId int64 `json:"client_id"`
}
const (
	headerXPublic = "X-Public"
	headerXClientId = "X-Client-Id"
	headerXUserId = "X-User-Id"
	paramAccessToken = "accesstoken"
)
var (
	oauthRequestClient = rest.RequestBuilder{
		Timeout: 100 * time.Millisecond,
		BaseURL: "http://localhost:8080",
	}
)
func IsPlublic(r *http.Request) bool {
	if r == nil {
		return true
	}
	return r.Header.Get(headerXPublic) == "true"
}
func GetClientId(r *http.Request) int64{
	if r == nil {
		return 0
	}
	clientId, err := strconv.ParseInt(r.Header.Get(headerXClientId), 10, 64)
	if err != nil {
		return 0
	}
	return clientId
}
func GetUserId(r *http.Request) int64{
	if r == nil {
		return 0
	}
	userId, err := strconv.ParseInt(r.Header.Get(headerXUserId), 10, 64)
	if err != nil {
		return 0
	}
	return userId

}
func AuthenticateRequest(r *http.Request) *errors.RestErr{
	if r == nil {
		return nil
	}
	// Cleaning Request Header
	cleanRequest(r)
	accessTokenId := strings.TrimSpace(r.URL.Query().Get(paramAccessToken))
	//URL = http://host_name/resource?accessToken=xyz123
	if accessTokenId == "" {
		return nil
	}
	at, err := getAccessToken(accessTokenId)
	if err != nil {
		if err.Status == http.StatusNotFound {
			return nil
		}
		return err
	}
	r.Header.Add(headerXClientId,strconv.Itoa(int(at.ClientId)))
	r.Header.Add(headerXUserId,strconv.Itoa(int(at.UserId)))

	return nil
}
func cleanRequest(r *http.Request){
	if r == nil {
		return
	}
	r.Header.Del(headerXClientId)
	r.Header.Del(headerXUserId)
}

func getAccessToken(tokenId string) (*accessToken, *errors.RestErr){
	resp := oauthRequestClient.Get(fmt.Sprintf("/oauth/access_token/%s",tokenId))
	if resp == nil || resp.Response == nil {
		return nil, errors.NewInternalServerError("Invalid RestClient response to get Access Token")
	}
	if resp.StatusCode > 299 {
		apiErr, err := errors.NewRestErrorFromBytes(resp.Bytes())
		if err != nil {
			return nil, errors.NewInternalServerError("Interface error while trying get access token")
		}
		return nil, apiErr
	}

	var at accessToken
	if err := json.Unmarshal(resp.Bytes(), &at); err != nil {
		return nil, errors.NewInternalServerError("Error unmarshall access token response")
	}
	return &at, nil
}

