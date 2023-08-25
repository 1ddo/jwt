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

func (r *Repository) IsValidAPIUser(au string) bool {
	qry := "SELECT * FROM goa_api_key WHERE api_user = $1 AND status = 'A'"
	ps, err := r.DB.Prepare(qry)

	if err != nil {
		panic(err.Error())
	}

	rows, err := ps.Query(au)
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
