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
	"time"
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

type addMailboxes struct {
	id		int64
	action	uint8
}

const (
	MBX_INSERT = 1
	MBX_DELETE = 2
)

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

	// Set database connection settings
	timeout, err := time.ParseDuration(Config.DB.ConnectionMaxLifeTime)
	if err != nil {
		timeout = 0
	}
	db_conn.SetConnMaxLifetime(timeout)
	db_conn.SetMaxOpenConns(Config.DB.MaxOpenConnections)
	db_conn.SetMaxIdleConns(Config.DB.MaxIdleConnections)


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

func (db *Database) addMailboxes(mailboxes map[string]*addMailboxes) error {
	
	if *debug {
		log.Println("[DEBUG] Modifying Mailboxes: ", len(mailboxes))
	}
	
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	
	for mbx_name, mbx_struct := range mailboxes {
		switch mbx_struct.action {
		case MBX_INSERT:
			tx.Stmt(db.queries["insert_aps_mailbox"]).Exec(mbx_struct.id, mbx_name)
		case MBX_DELETE:
			tx.Stmt(db.queries["delete_aps_mailbox"]).Exec(mbx_struct.id)
		}
	}

	err = tx.Commit()
	if err != nil {
		return err
	}

	return nil
}

func (db *Database) addRegistration(username, accountId, deviceToken string, mailboxes []string) error {

	s := strings.Split(username, "@")
	var (
		mbxid uint32
		apsid int64
		aps_mbxid int64
		aps_mbx_name string
	)
	query := db.queries

	// Get mailbox id
	err := query["select_mbx_id"].QueryRow(s[0], s[1]).Scan(&mbxid)
	if err != nil {
		return err
	}
	if *debug {
		log.Println("[DEBUG] Query Mailbox ID:", mbxid)
	}
	
	// Get or insert account into aps table
	err = query["select_aps_settings_id"].QueryRow(mbxid, accountId, deviceToken).Scan(&apsid)
	switch {
	case err == sql.ErrNoRows:
		res, err := query["insert_aps"].Exec(mbxid, accountId, deviceToken)
		if err != nil {
			return err
		}
		apsid, err = res.LastInsertId()
		if *debug {
			log.Println("[DEBUG] Registered Account: ", mbxid, apsid)
		}
	case err != nil:
		return err
	}
	
	// Add mailboxes to a map
	map_mailboxes := make(map[string]*addMailboxes, 4)
	for _, m := range mailboxes {
		map_mailboxes[m] = &addMailboxes{apsid, MBX_INSERT}
	}

	// Figure out which mailboxes need to be added/removed
	rows, err := query["get_aps_mailboxes"].Query(apsid)
	if err != nil {
		if err == sql.ErrNoRows {
			err = db.addMailboxes(map_mailboxes)
		}
		return err
	}
	defer rows.Close()
	
	for rows.Next() {
		_ = rows.Scan(&aps_mbxid, &aps_mbx_name)
		if _, ok := map_mailboxes[aps_mbx_name]; ok {
			delete(map_mailboxes, aps_mbx_name)
		} else {
			map_mailboxes[aps_mbx_name] = &addMailboxes{aps_mbxid, MBX_DELETE}
		}
	}
	rows.Close()
	
	// Add mailboxes if required
	if len(map_mailboxes) > 0 {
		err = db.addMailboxes(map_mailboxes)
		if err != nil {
			return err
		}
	}

	return nil
}

func (db *Database) findRegistrations(username, mailbox string) ([]Registration, error) {
	var registrations []Registration
	s := strings.Split(username, "@")
	rows, err := db.queries["find_registration"].Query(mailbox, s[0], s[1])
	if err != nil {
		if err == sql.ErrNoRows {
			err = nil
		}
		return registrations, err
	}
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
