package db

import (
	"database/sql"

	"github.com/labstack/gommon/log"
	_ "github.com/mattn/go-sqlite3"
)

func DB() *sql.DB {
	result, err := sql.Open("sqlite3", "./black.db")
	if err != nil {
		log.Fatalf("Error connecting to the database : %s", err)
	}
	return result
}
