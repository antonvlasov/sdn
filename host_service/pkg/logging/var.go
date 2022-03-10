package logging

import (
	"database/sql"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

const (
	dbpath = "/home/mininet/project/data/logs.db"
	table  = "logs"
)

var db *sql.DB

func init() {
	var err error
	db, err = sql.Open("sqlite3", dbpath)
	if err != nil {
		log.Fatal(err)
	}
}
