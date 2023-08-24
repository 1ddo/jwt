package main

import (
	"database/sql"

	_ "github.com/lib/pq"
)

type Repository struct {
	db *sql.DB
}

func NewRepo(db *sql.DB) *Repository {
	return &Repository{
		db: db,
	}
}

func NewDBCon(connStr string) *sql.DB {
	var err error
	// must be transferred to config file
	// connStr = "postgres://goalert:root@localhost/goalert?sslmode=disable"
	db, err := sql.Open("postgres", connStr)

	if err != nil {
		panic(err)
	}

	if err = db.Ping(); err != nil {
		panic(err)
	}

	log.Info("Connection to database has been established.")

	return db
}

func IsValidAPIUser(r *Repository, au string) bool {
	qry := "SELECT * FROM goa_api_key WHERE api_user = $1 AND status = 'A'"
	ps, err := r.db.Prepare(qry)

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
