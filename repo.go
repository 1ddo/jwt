package main

import (
	"database/sql"
	"regexp"

	"github.com/1ddo/jwt/keyring"

	_ "github.com/lib/pq"
	logr "github.com/sirupsen/logrus"
)

type Repository struct {
	DB         *sql.DB
	Log        *logr.Logger
	Keys       keyring.Keys
	SECRET_KEY string
}

type APIKey struct {
	ApiKey      string
	ApiUser     string
	Status      string
	CreatedTime string
}

func NewRepository() *Repository {
	return &Repository{
		Log:        logr.New(),
		SECRET_KEY: "Key137&*#!~c(8~=2?.?%b74",
		Keys:       keyring.Keys{},
	}
}

func (r *Repository) SetDB(constr string) {
	var err error
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

	apk, err := r.Keys.Encrypt("API USER KEY", []byte(ak.ApiKey))
	apks := string(apk)

	if err != nil {
		panic("Error encrypting api key: " + err.Error())
	}

	ps.Exec(apks, ak.ApiUser, "A")

	r.Log.Info("API Key has been inserted: " + apks)
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

	r.CheckError(err)

	defer rows.Close()

	result := make(map[int]APIKey)

	for rows.Next() {
		var api_key string
		var api_user string
		var status string
		var created_time string

		err = rows.Scan(&api_key, &api_user, &status, &created_time)
		r.CheckError(err)

		result[rc] = APIKey{
			ApiKey:      api_key,
			ApiUser:     api_user,
			Status:      status,
			CreatedTime: created_time,
		}

		rc++
	}

	r.CheckError(err)

	return result
}

func (r *Repository) IsUserExist(ak string) bool {
	qry := "SELECT * FROM goa_api_key WHERE api_user = $1 AND status = 'A'"
	ps, err := r.DB.Prepare(qry)

	if err != nil {
		panic("Error getting API Key info from DB: " + err.Error())
	}

	rows, err := ps.Query(ak)
	rc := 0

	r.CheckError(err)

	defer rows.Close()

	for rows.Next() {
		var api_key string
		var api_user string
		var status string
		var created_time string

		err = rows.Scan(&api_key, &api_user, &status, &created_time)
		r.CheckError(err)

		rc++
	}

	r.CheckError(err)

	return rc > 0
}

func (r *Repository) IsValidAPIUser(au string, uid string) bool {
	qry := "SELECT * FROM goa_api_key WHERE api_user = $1 AND status = 'A'"
	ps, err := r.DB.Prepare(qry)

	if err != nil {
		panic("Error getting API User info from DB: " + err.Error())
	}

	rows, err := ps.Query(uid)
	rc := 0
	var dbak []byte

	r.CheckError(err)

	defer rows.Close()

	for rows.Next() {
		var api_key string
		var api_user string
		var status string
		var created_time string

		err = rows.Scan(&api_key, &api_user, &status, &created_time)
		r.CheckError(err)

		r.Log.Info("API KEY FROM DB: " + api_key)
		r.Log.Info("API KEY FROM DB TRIMED: " + r.TrimSpaceNewlineInString(api_key))

		dbak, _, err = r.Keys.Decrypt([]byte(r.TrimSpaceNewlineInString(api_key)))

		if err != nil {
			panic("Error encrypting api key: " + err.Error())
		}

		rc++
	}

	r.CheckError(err)
	r.Log.Info("Decrypted Key: " + string(dbak))

	return string(dbak) == au
}

func (r *Repository) CheckError(err error) {
	if err != nil {
		panic(err)
	}
}

func (r *Repository) TrimSpaceNewlineInString(s string) string {
	re := regexp.MustCompile(` +\r?\n +`)

	return re.ReplaceAllString(s, " ")
}
