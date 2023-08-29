package main

import (
	"database/sql"

	_ "github.com/lib/pq"
	logr "github.com/sirupsen/logrus"
)

type Repository struct {
	DB  *sql.DB
	Log *logr.Logger
}

type APIKey struct {
	ApiKey      string
	ApiUser     string
	Status      string
	CreatedTime string
}

func NewRepository() *Repository {
	return &Repository{
		Log: logr.New(),
	}
}

func (r *Repository) SetDB(constr string) {
	var err error
	// must be transferred to config file
	// connStr = "postgres://goalert:root@localhost/goalert?sslmode=disable"
	db, err := sql.Open("postgres", constr)

	if err != nil {
		panic(err)
	}

	if err = db.Ping(); err != nil {
		panic(err)
	}

	r.Log.Info("Connection to database has been established.")

	r.DB = db
}

func (r *Repository) AddAPIKey(ak *APIKey) {
	qry := "INSERT INTO goa_api_key VALUES($1, $2, $3)"
	ps, err := r.DB.Prepare(qry)

	if err != nil {
		panic("Error inserting API Key from DB: " + err.Error())
	}

	e := NewEncryption()
	apk, err := e.Encrypt(ak.ApiKey)

	if err != nil {
		panic("Error encrypting api key: " + err.Error())
	}

	ps.Exec(apk, ak.ApiUser, "A")

	r.Log.Info("API Key has been inserted: " + apk)
}

func (r *Repository) RemoveAPIKey(ak string) {
	qry := "DELETE FROM goa_api_key WHERE api_key = $1"
	ps, err := r.DB.Prepare(qry)

	if err != nil {
		panic("Error removing API Key from DB: " + err.Error())
	}

	ps.Exec(ak)
}

func (r *Repository) GetAllAPIKeys() map[int]APIKey {
	qry := "SELECT * FROM goa_api_key"
	ps, err := r.DB.Prepare(qry)

	if err != nil {
		panic("Error retrieving API Key from DB: " + err.Error())
	}

	rows, err := ps.Query()
	rc := 0

	CheckError(err)

	defer rows.Close()

	result := make(map[int]APIKey)

	for rows.Next() {
		var api_key string
		var api_user string
		var status string
		var created_time string

		err = rows.Scan(&api_key, &api_user, &status, &created_time)
		CheckError(err)

		result[rc] = APIKey{
			ApiKey:      api_key,
			ApiUser:     api_user,
			Status:      status,
			CreatedTime: created_time,
		}

		rc++
	}

	CheckError(err)

	return result
}

func (r *Repository) IsAPIKeyExist(ak string) bool {
	qry := "SELECT * FROM goa_api_key WHERE api_key = $1 AND status = 'A'"
	ps, err := r.DB.Prepare(qry)

	if err != nil {
		panic("Error getting API Key info from DB: " + err.Error())
	}

	e := NewEncryption()
	apk, err := e.Encrypt(ak)

	if err != nil {
		panic("Error encrypting api key: " + err.Error())
	}

	rows, err := ps.Query(apk)
	rc := 0

	CheckError(err)

	defer rows.Close()

	for rows.Next() {
		var api_key string
		var api_user string
		var status string
		var created_time string

		err = rows.Scan(&api_key, &api_user, &status, &created_time)
		CheckError(err)

		rc++
	}

	CheckError(err)

	return rc > 0
}

func (r *Repository) IsValidAPIUser(au string) bool {
	qry := "SELECT * FROM goa_api_key WHERE api_key = $1 AND status = 'A'"
	ps, err := r.DB.Prepare(qry)

	if err != nil {
		panic("Error getting API User info from DB: " + err.Error())
	}

	e := NewEncryption()
	apk, err := e.Encrypt(au)

	if err != nil {
		panic("Error encrypting api key: " + err.Error())
	}

	rows, err := ps.Query(apk)
	rc := 0

	CheckError(err)

	defer rows.Close()

	for rows.Next() {
		var api_key string
		var api_user string
		var status string
		var created_time string

		err = rows.Scan(&api_key, &api_user, &status, &created_time)
		CheckError(err)

		rc++
	}

	CheckError(err)

	return rc > 0
}

func CheckError(err error) {
	if err != nil {
		panic(err)
	}
}
