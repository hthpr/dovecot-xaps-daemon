//
// The MIT License (MIT)
//
// Copyright (c) 2015 Stefan Arentz <stefan@arentz.ca>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//

package main

import (
	"strings"
	"log"
	"strconv"
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
	"fmt"
)

type Registration struct {
	DbId        int
	DeviceToken string
	AccountId   string
}

type Database struct {
	conn     *sql.DB
	queries map[string]*sql.Stmt
}

func connectDatabase() (*Database, error) {

	// Connect to Database
	host := "@tcp(" + Config.DB.Host + ":" + strconv.FormatUint(uint64(Config.DB.Port), 10) + ")/"
	if Config.DB.Socket != "" {
		host = "@unix(" + Config.DB.Socket + ")/"
	}

	db_conn, err := sql.Open("mysql", Config.DB.User + ":" + Config.DB.Password + host + Config.DB.Name + "?" + Config.DB.Options)
        if err != nil {
		return nil, err
	}

        err = db_conn.Ping()
        if err != nil {
		return nil, err
        }

	var db Database = Database{conn: db_conn, queries: make(map[string]*sql.Stmt)}

	// Prepare SQL Queries
	for name, sql := range Config.DB.Queries {
		db.queries[name], err = db.conn.Prepare(sql.Sql)
		if err != nil {
			return nil, fmt.Errorf("Unable to prepare query '%s': %v", name, err)
		}
	}

	return &db, nil
}

func (db *Database) addRegistration(username, accountId, deviceToken string, mailboxes []string) error {

	s := strings.Split(username, "@")
	var mbxid int
	query := db.queries

	err := query["select_mbx_id"].QueryRow(s[0], s[1]).Scan(&mbxid)
	if err != nil {
		return err
	}
	if *debug {
		log.Println("[DEBUG] Query Mailbox ID:", mbxid)
	}

	res, err := query["insert_aps"].Exec(mbxid, accountId, deviceToken)
	if err != nil {
		return err
	}

	mbxapsid, err := res.LastInsertId()
	if *debug {
		log.Println("[DEBUG] Last Insert ID:", mbxapsid)
	}

	res, err = query["delete_aps_mailboxes"].Exec(mbxapsid)
	if err != nil {
		return err
        }

        for _, m := range mailboxes {
		 query["insert_aps_mailboxes"].Exec(mbxapsid, m)
        }

	return nil
}

func (db *Database) findRegistrations(username, mailbox string) ([]Registration, error) {
	var registrations []Registration
	s := strings.Split(username, "@")
	rows, _ := db.queries["find_registration"].Query(mailbox, s[0], s[1])
	defer rows.Close()

	var (
		dbid int
		devicetoken string
		accountId string
	)

	for rows.Next() {
		_ = rows.Scan(&dbid, &accountId, &devicetoken)
		registrations = append(registrations,
			Registration{DbId: dbid, DeviceToken: devicetoken, AccountId: accountId})
		if *debug {
			log.Println("[DEBUG] Found Registration:", devicetoken, accountId)
		}
	}

	return registrations, nil
}

func (db *Database) deleteRegistration(reg Registration) error {

	_, err := db.queries["delete_registration"].Exec(reg.DbId)
	if err != nil {
		return err
	}

	return nil
}
