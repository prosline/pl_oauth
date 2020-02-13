package oauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/mercadolibre/golang-restclient/rest"
	"github.com/prosline/pl_util/utils/rest_errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type oauthClient struct{}


type accessToken struct {
	Id       string `json:"id"`
	UserId   int64  `json:"user_id"`
	ClientId int64  `json:"client_id"`
}

const (
	headerXPublic    = "X-Public"
	headerXClientId  = "X-Client-Id"
	headerXCallerId  = "X-Caller-Id"
	headerXUserId    = "X-User-Id"
	paramAccessToken = "access_token"
)

var (
	oauthRequestClient = rest.RequestBuilder{
		BaseURL: "http://localhost:8080",
		Timeout: 200 * time.Millisecond,
	}
)

func IsPlublic(r *http.Request) bool {
	if r == nil {
		return true
	}
	return r.Header.Get(headerXPublic) == "true"
}
func GetClientId(r *http.Request) int64 {
	if r == nil {
		return 0
	}
	clientId, err := strconv.ParseInt(r.Header.Get(headerXClientId), 10, 64)
	if err != nil {
		return 0
	}
	return clientId
}
func GetUserId(r *http.Request) int64 {
	if r == nil {
		return 0
	}
	userId, err := strconv.ParseInt(r.Header.Get(headerXUserId), 10, 64)
	if err != nil {
		return 0
	}
	return userId
}
func GetCallerId(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	callerId, err := strconv.ParseInt(request.Header.Get(headerXCallerId), 10, 64)
	if err != nil {
		return 0
	}
	return callerId
}
func AuthenticateRequest(r *http.Request) rest_errors.RestErr {
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
		if err.Status() == http.StatusNotFound {
			return nil
		}
		return err
	}
	r.Header.Add(headerXClientId, strconv.Itoa(int(at.ClientId)))
	r.Header.Add(headerXCallerId, strconv.Itoa(int(at.UserId)))

	return nil
}
func cleanRequest(r *http.Request) {
	if r == nil {
		return
	}
	r.Header.Del(headerXClientId)
	r.Header.Del(headerXUserId)
}

func getAccessToken(tokenId string) (*accessToken, rest_errors.RestErr) {
	urlQuery := fmt.Sprintf("/oauth/access_token/%s", tokenId)
	fmt.Println("Oauth URL Query = ", urlQuery)
	resp := oauthRequestClient.Get(fmt.Sprintf("/oauth/access_token/%s", tokenId))
	if resp == nil || resp.Response == nil {
		return nil, rest_errors.NewInternalServerError("Invalid RestClient response to get Access Token", errors.New("Session timeout"))
	}
	if resp.StatusCode > 299 {
		apiErr, err := rest_errors.NewRestErrorFromBytes(resp.Bytes())
		if err != nil {
			return nil, rest_errors.NewInternalServerError("Interface error while trying get access token", err)
		}
		return nil, apiErr
	}

	var at accessToken
	if err := json.Unmarshal(resp.Bytes(), &at); err != nil {
		return nil, rest_errors.NewInternalServerError("Error unmarshall access token response", errors.New("Error processing Json"))
	}
	return &at, nil
}
