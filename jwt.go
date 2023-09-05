package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	_ "github.com/lib/pq"
	logr "github.com/sirupsen/logrus"
)

type JWT struct {
	SecretToken []byte
	Log         *logr.Logger
	Token       Token
	Repo        Repository
}

type Token struct {
	Token     string
	IssuedAt  string
	ExpiresAt string
	NoExpiry  bool
	User      string
}

func NewJWT() JWT {
	return JWT{
		SecretToken: []byte("$JWT1SUPER2SECRET3TOKEN$"),
		Log:         logr.New(),
		Token: Token{
			Token:     "",
			IssuedAt:  "",
			ExpiresAt: "",
			NoExpiry:  false,
		},
	}
}

/*
  - Default: JWT is set to expire for a day
    iss (issuer): Issuer of the JWT.
    sub (subject): Subject of the JWT (the user).
    aud (audience): The JWT intended recipient or audience.
    exp (expiration time): The time the JWT expires.
    nbf (not before policy): Identifies the time before which JWT can not be accepted into processing.
    iat (issued at time): Identifies the time at which the JWT was issued. This can be used to establish the age of the JWT or the exact time the token was generated.
    jti (JWT ID): Unique identifier; this can be used to prevent the JWT from being used more than once.
    *
*/
func (j *JWT) CreateJWT() (Token, error) {
	var nt Token
	var et int64     // expiry time
	ct := time.Now() // issuedat
	// check if no expiry flag is set
	if !j.Token.NoExpiry {
		et = ct.Add(24 * time.Hour).Unix()
		nt.ExpiresAt = ct.Add(24 * time.Hour).Format("2006-01-02 15:04:05")
	} else {
		j.Log.Info("Token has been set to not expired.")
	}
	// to update when there's additional info to add
	mc := jwt.MapClaims{
		"IssuedAt":  ct,
		"ExpiresAt": et,
	}

	t := jwt.NewWithClaims(jwt.SigningMethodHS256, mc)
	c := t.Claims.(jwt.MapClaims)
	// sample claims information
	c["exp"] = et
	c["iss"] = "JWT Golang POC Project"
	c["sub"] = "Test JWT Golang"
	c["aud"] = "Devs"
	c["role"] = "Developer" // custom claims
	c["usr"] = j.Token.User // custom claims
	c["jti"] = j.GenerateRandomString(32)
	c["nxp"] = j.Token.NoExpiry

	if !j.Token.NoExpiry {
		c["iat"] = ct
	}

	ts, err := t.SignedString(j.SecretToken)

	if err != nil {
		fmt.Println(err.Error())

		return nt, err
	}

	nt.Token = ts
	nt.IssuedAt = ct.Format("2006-01-02 15:04:05")
	nt.NoExpiry = j.Token.NoExpiry

	return nt, nil
}

func (j *JWT) GenerateRandomString(length int) string {
	b := make([]byte, length)
	_, err := rand.Read(b)

	if err != nil {
		panic(err)
	}

	return base64.StdEncoding.EncodeToString(b)
}

func (j *JWT) ValidateJWT(next func(w http.ResponseWriter, r *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		j.Log.Info("Token is being validated...")
		if r.Header["Token"] != nil {
			c := jwt.MapClaims{}
			token, err := jwt.ParseWithClaims(r.Header["Token"][0], &c, func(t *jwt.Token) (interface{}, error) {
				_, ok := t.Method.(*jwt.SigningMethodHMAC)

				if !ok {
					j.Log.Error("Token has been validated and is not Authorized.")

					w.WriteHeader(http.StatusUnauthorized)
					w.Write([]byte("Not Authorized"))
				}

				return j.SecretToken, nil
			})

			if err != nil {
				j.Log.Error("Not Authorized: " + err.Error())

				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("Not Authorized"))
			}

			// continue request if token is valid
			if token != nil && token.Valid {
				j.Log.Infof("JWT ID (jti): %s", c["jti"])
				j.Log.Infof("User (usr): %s", c["usr"])
				j.Log.Infof("Role (role): %s", c["role"])
				j.Log.Infof("No Expiry (nxp): %t", c["nxp"])
				j.Log.Infof("Expires At (exp): %f", c["exp"])
				j.Log.Infof("Issuer (iss): %s", c["iss"])
				j.Log.Infof("Subject (sub): %s", c["sub"])
				j.Log.Infof("Audience (aud): %s", c["aud"])
				j.Log.Infof("Not Before Policy) nbf: %f", c["nbf"])
				j.Log.Infof("Issued At Time (iat): %f", c["iat"])

				next(w, r)
			}
		} else {
			j.Log.Error("Token is empty.")

			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Not Authorized"))
		}
	})
}

func (j *JWT) GetJWT(w http.ResponseWriter, r *http.Request) {
	if r.Header["Access"] != nil {
		// get access key header
		au := r.Header["Access"][0]
		// get user
		ak := r.URL.Query().Get("api_user")
		akt := strings.TrimSpace(ak)
		// validate Access key in header
		j.Log.Info("Checking user key: " + akt)
		if j.Repo.IsValidAPIUser(au, akt) {
			_, ok := r.Header["Token-No-Expiry"]
			j.Token.NoExpiry = ok // setting token to no expiry
			j.Token.User = akt
			t, err := j.CreateJWT()

			if err != nil {
				j.Log.Error("Error creating JWT token." + err.Error())

				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("Error creating JWT token: " + err.Error()))
			}

			w.Header().Set("Content-Type", "application/json")
			jrp, err := json.Marshal(t)

			if err != nil {
				j.Log.Error("Error converting JWT to JSON format." + err.Error())

				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("Error creating JWT token: " + err.Error()))
			}

			j.Log.Info("JWT token has been created.")

			w.Write(jrp)

			return
		} else {
			j.Log.Error("Access key is invalid.")

			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Not Authorized"))
		}
	} else {
		j.Log.Error("Access key is empty.")

		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Not Authorized"))
	}
}

func (j *JWT) AddAPIKey(w http.ResponseWriter, r *http.Request) {
	au := r.URL.Query().Get("api_user")
	ak := r.URL.Query().Get("api_key")

	if strings.TrimSpace(ak) != "" {
		if j.Repo.IsUserExist(au) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("The API Key already exist. Please modify the API Key and try again."))
		} else {
			j.Log.Info("API KEY: " + ak)
			j.Repo.AddAPIKey(&APIKey{
				ApiKey:  ak,
				ApiUser: au, // to be replaced by actual user impl
				Status:  "A",
			})

			w.Write([]byte("The new API Key has been added."))
		}
	} else {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("API Key Value Not Found"))
	}
}

func (j *JWT) GetAPIKey(w http.ResponseWriter, r *http.Request) {
	js, err := json.Marshal(j.Repo.GetAllAPIKeys())

	if err != nil {
		fmt.Println(err)
		return
	}

	w.Write([]byte(js))
}
