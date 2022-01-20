package service

import (
	"database/sql"
	"log"
	"os"
	"os/signal"
	"syscall"

	_ "github.com/mattn/go-sqlite3"
)

const (
	dbPath = "/home/mininet/project/data/logs.db"
)

var db *sql.DB

func init() {
	var err error
	db, err = sql.Open("sqlite3",
		dbPath)
	if err != nil {
		log.Fatal(err)
	}
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		db.Close()
	}()
}

func LogTiming(randomID, hostService string, iterationNumber uint64, startTime, endTime int64) error {
	stmt, err := db.Prepare(`
	INSERT INTO timings(random_id,host_service, iteration_number, start_time, end_time)
		VALUES(?,?,?,?,?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	_, err = stmt.Exec(randomID, hostService, iterationNumber, startTime, endTime)
	if err != nil {
		return err
	}
	return nil
}
