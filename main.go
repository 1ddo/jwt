package main

import (
	"fmt"
	"net/http"
	"os"

	_ "github.com/lib/pq"
	logr "github.com/sirupsen/logrus"
)

func HelloWithToken(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello World!")
}

func CheckError(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	j := NewJWT()
	//log.SetFormatter(&log.JSONFormatter{})
	j.Log.SetOutput(os.Stdout)
	j.Log.SetLevel(logr.DebugLevel)

	r := *NewRepository()
	r.SetDB("postgres://goalert:root@localhost/goalert?sslmode=disable")
	r.Log.SetOutput(os.Stdout)
	r.Log.SetLevel(logr.DebugLevel)

	j.Repo = r

	http.Handle("/hello", j.ValidateJWT(HelloWithToken))
	http.HandleFunc("/jwt", j.GetJWT)

	http.ListenAndServe(":8080", nil)
}
