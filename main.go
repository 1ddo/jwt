package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
	_ "github.com/lib/pq"
	logr "github.com/sirupsen/logrus"
)

var SECRET_TOKEN = []byte("SECRET TOKEN")
var log = logr.New()

// Token represents an authentication token.
type Token struct {
	Token     string
	IssuedAt  string
	ExpiresAt string
}

func NewJWT(noExp bool) (Token, error) {
	var nt Token
	var et int64     // expiry time
	ct := time.Now() // issuedat
	// check if no expiry flag is set
	if !noExp {
		et = ct.Add(24 * time.Hour).Unix()
		nt.ExpiresAt = ct.Add(24 * time.Hour).Format("2006-01-02 15:04:05")
	} else {
		log.Info("Token has been set to not expired.")
	}
	// to update when there's additional info to add
	mc := jwt.MapClaims{
		"IssuedAt":  ct,
		"ExpiresAt": et,
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, mc)

	// Default: JWT is set to expire for a day
	c := t.Claims.(jwt.MapClaims)
	c["exp"] = et

	ts, err := t.SignedString(SECRET_TOKEN)

	if err != nil {
		fmt.Println(err.Error())

		return nt, err
	}

	nt.Token = ts
	nt.IssuedAt = ct.Format("2006-01-02 15:04:05")

	return nt, nil
}

func ValidateJWT(next func(w http.ResponseWriter, r *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header["Token"] != nil {
			token, err := jwt.Parse(r.Header["Token"][0], func(t *jwt.Token) (interface{}, error) {
				_, ok := t.Method.(*jwt.SigningMethodHMAC)

				if !ok {
					log.Error("Token has been validated and is not Authorized. ")

					w.WriteHeader(http.StatusUnauthorized)
					w.Write([]byte("Not Authorized"))
				}

				return SECRET_TOKEN, nil
			})

			if err != nil {
				log.Error("Not Authorized: " + err.Error())

				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("Not Authorized: " + err.Error()))
			}

			if token.Valid {
				next(w, r)
			}
		} else {
			log.Error("Token is empty.")

			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Not Authorized"))
		}
	})
}

func (rp *Repository) GetJWT(w http.ResponseWriter, r *http.Request) {
	if r.Header["Access"] != nil {
		// get access key header
		au := r.Header["Access"][0]
		// validate Access key in header
		log.Info("Checking user key: " + au)
		if IsValidAPIUser(rp, au) {
			_, ok := r.Header["Token-No-Expiry"]
			t, err := NewJWT(ok)

			if err != nil {
				log.Error("Error creating JWT token." + err.Error())

				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("Error creating JWT token: " + err.Error()))
			}

			w.Header().Set("Content-Type", "application/json")
			jrp, err := json.Marshal(t)

			if err != nil {
				log.Error("Error converting JWT to JSON format." + err.Error())

				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("Error creating JWT token: " + err.Error()))
			}

			log.Info("JWT token has been created.")

			w.Write(jrp)

			return
		} else {
			log.Error("Access key is invalid.")

			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Not Authorized"))
		}
	} else {
		log.Error("Access key is empty.")

		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Not Authorized"))
	}
}

func HelloWithToken(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello World!")
}

func CheckError(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	//log.SetFormatter(&log.JSONFormatter{})
	log.SetOutput(os.Stdout)
	log.SetLevel(logr.DebugLevel)

	rp := Repository{
		db: NewDBCon("postgres://goalert:root@localhost/goalert?sslmode=disable"),
	}

	http.Handle("/hello", ValidateJWT(HelloWithToken))
	http.HandleFunc("/jwt", rp.GetJWT)

	http.ListenAndServe(":8080", nil)
}
