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
	"bufio"
	"crypto/x509"
	"errors"
	"flag"
	"encoding/json"
        "github.com/sideshow/apns2"
	"github.com/sideshow/apns2/certificate"
	"github.com/jinzhu/configor"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"strings"
)

const Version = "2.0"

type command struct {
	name string
	args map[string]interface{}
}

type Payload struct {
	Aps Aps `json:"aps"`
}

type Aps struct {
	AccountID string `json:"account-id"`
}

func (cmd *command) getStringArg(name string) (string, bool) {
	arg, ok := cmd.args[name].(string)
	return arg, ok
}

func (cmd *command) getListArg(name string) ([]string, bool) {
	arg, ok := cmd.args[name].([]string)
	return arg, ok
}

func parseListValue(value string) ([]string, error) {
	list := []string{}
	values := strings.Split(value[1:len(value)-1], ",")
	for _, value := range values {
		stringValue, err := parseStringValue(value)
		if err != nil {
			return nil, err
		}
		list = append(list, stringValue)
	}
	return list, nil
}

func parseStringValue(value string) (string, error) {
	return value[1 : len(value)-1], nil // TODO Escaping!
}

func parseCommand(line string) (command, error) {
	cmd := command{args: make(map[string]interface{})}

	parts := strings.SplitN(line, " ", 2)
	if len(parts) != 2 {
		return cmd, errors.New("Failed to parse: no name found")
	}

	cmd.name = parts[0]

	for _, pair := range strings.Split(parts[1], "\t") {
		nameAndValue := strings.SplitN(pair, "=", 2)
		if len(nameAndValue) != 2 {
			return cmd, errors.New("Failed to parse: no name/value pair found")
		}

		switch {
		case strings.HasPrefix(nameAndValue[1], `"`) && strings.HasSuffix(nameAndValue[1], `"`):
			value, err := parseStringValue(nameAndValue[1])
			if err != nil {
				return cmd, err
			}
			cmd.args[nameAndValue[0]] = value
		case strings.HasPrefix(nameAndValue[1], "(") && strings.HasSuffix(nameAndValue[1], ")"):
			value, err := parseListValue(nameAndValue[1])
			if err != nil {
				return cmd, err
			}
			cmd.args[nameAndValue[0]] = value
		default:
			return cmd, errors.New("Failed to parse: invalid value in key/value pair")
		}
	}

	return cmd, nil
}

var debug = flag.Bool("debug", false, "enable debug logging")

func topicFromCertificate(cert *x509.Certificate) (string, error) {
	if len(cert.Subject.Names) == 0 {
		return "", errors.New("Subject.Names is empty")
	}

	oidUid := []int{0, 9, 2342, 19200300, 100, 1, 1}
	if !cert.Subject.Names[0].Type.Equal(oidUid) {
		return "", errors.New("Did not find a Subject.Names[0] with type 0.9.2342.19200300.100.1.1")
	}

	return cert.Subject.Names[0].Value.(string), nil
}

func SetAccountID(accountid string) []byte {
        p := Payload{}
        p.Aps.AccountID = accountid
        aps, _ := json.Marshal(p)
        return aps
}

type SQLQueries struct {
    Sql	string
}

var Config = struct {
	Certificate string `default:"/etc/xapsd/certificate.pem"`
	Socket      string `default:"/var/run/xapsd/xapsd.sock"`

	DB struct {
		Host	 string
		Port	 uint16 `default:"3306"`
		Socket	 string
		Name	 string
		User	 string `default:"root"`
		Password string `required:"true"`
		Options  string `default:"timeout=5s&collation=utf8mb4_unicode_ci"`
		Queries map[string]SQLQueries
	}
}{}

func main() {
	config := flag.String("config", "/etc/xapsd.toml", "path to configuration file")
	socket := flag.String("socket", "", "path to the socket for Dovecot")
	certfile := flag.String("certificate", "", "path to the pem/p12 file containing the key and certificate")
	flag.Parse()

	configor.Load(&Config, *config)

	if *certfile != "" {
		Config.Certificate = *certfile
	}

        if *socket != "" {
                Config.Socket = *socket
        }

	db, err := connectDatabase()
	if err != nil {
		log.Fatal(err)
	}
	defer db.conn.Close()

	for name, sql := range db.queries {
		defer sql.Close()
        }

	// Delete the socket if it already exists
	if _, err := os.Stat(Config.Socket); err == nil {
		if err := os.Remove(Config.Socket); err != nil {
			log.Fatal("Could not delete existing socket: ", Config.Socket, err.Error())
		}
	}

	if *debug {
		log.Println("[DEBUG] Listening on UNIX socket at", Config.Socket)
	}

	listener, err := net.Listen("unix", Config.Socket)
	if err != nil {
		log.Fatal("Could not create socket: ", err.Error())
	}
	defer listener.Close()
	defer os.Remove(Config.Socket)

	// TODO What is the proper way to limit Dovecot to this socket
	if err := os.Chmod(Config.Socket, 0777); err != nil {
		log.Fatal("Could not chmod socket: ", err.Error())
	}

	if *debug {
		log.Println("[DEBUG] Parsing", Config.Certificate, "to obtain APNS Topic")
	}

        cert, err := certificate.FromPemFile(Config.Certificate, "")
        if err != nil {
		log.Println("PEM Certificate Loading Error: ", err)
		cert, err = certificate.FromP12File(Config.Certificate, "")
		if err != nil { 
			log.Fatal("P12 Certificate Loading Error: ", err)
		}
	}

	topic, err := topicFromCertificate(cert.Leaf)
	if err != nil {
		log.Fatal("Could not parse apns topic from certificate: ", err.Error())
	}

	if *debug {
		log.Println("[DEBUG] Topic is", topic)
	}

	if *debug {
		log.Println("[DEBUG] Creating APNS client to", apns2.HostProduction)
	}

	c := apns2.NewClient(cert).Production()

	signalChannel := make(chan os.Signal, 2)
	quit := make(chan bool)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signalChannel
		close(quit)
		listener.Close()
	}()

	log.Printf("Starting xapsd %s on %s", Version, Config.Socket)

	Accept:
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-quit:
				log.Printf("Shutting Down xapsd %s", Version)
				break Accept
			default:
				log.Println("Failed to accept connection: ", err.Error())
				os.Exit(1)
			}
			continue
		}

		if *debug {
			log.Println("[DEBUG] Accepted a connection")
		}

		go handleRequest(conn, c, db, topic)


	}
}

func handleRequest(conn net.Conn, client *apns2.Client, db *Database, topic string) {
	defer conn.Close()

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		if *debug {
			log.Println("[DEBUG] Received request:", scanner.Text())
		}

		command, err := parseCommand(scanner.Text())
		if err != nil {
			log.Println("Reading from socket: ", err)
		}

		switch command.name {
		case "REGISTER":
			handleRegister(conn, command, client, db, topic)
		case "NOTIFY":
			handleNotify(conn, command, client, db)
		default:
			writeError(conn, "Unknown command")
		}
	}

	if err := scanner.Err(); err != nil {
		log.Println("Reading from socket: ", err)
	}
}

//
// Handle the REGISTER command. It looks as follows:
//
//  REGISTER aps-account-id="AAA" aps-device-token="BBB"
//     aps-subtopic="com.apple.mobilemail"
//     dovecot-username="stefan"
//     dovecot-mailboxes=("Inbox","Notes")
//
// The command returns the aps-topic, which is the common name of
// the certificate issued by OS X Server for email push
// notifications.
//

func handleRegister(conn net.Conn, cmd command, client *apns2.Client, db *Database, topic string) {
	// Make sure the subtopic is ok
	subtopic, ok := cmd.getStringArg("aps-subtopic")
	if !ok {
		writeError(conn, "Missing apis-subtopic argument")
		return
	}
	if subtopic != "com.apple.mobilemail" {
		writeError(conn, "Unknown aps-subtopic")
		return
	}

	// Make sure we got the required parameters
	accountId, ok := cmd.getStringArg("aps-account-id")
	if !ok {
		writeError(conn, "Missing aps-account-id argument")
		return
	}
	deviceToken, ok := cmd.getStringArg("aps-device-token")
	if !ok {
		writeError(conn, "Missing aps-device-token argument")
		return
	}
	username, ok := cmd.getStringArg("dovecot-username")
	if !ok {
		writeError(conn, "Missing dovecot-username argument")
		return
	}
	mailboxes, ok := cmd.getListArg("dovecot-mailboxes")
	if !ok {
		writeError(conn, "Missing dovecot-mailboxes argument")
		return
	}

	// Register this email/account-id/device-token combination
	err := db.addRegistration(username, accountId, deviceToken, mailboxes)
	if err != nil {
		writeError(conn, "Failed to register client: "+err.Error())
		return
	}

	writeSuccess(conn, topic)
}

//
// Handle the NOTIFY command. It looks as follows:
//
//  NOTIFY dovecot-username="stefan" dovecot-mailbox="Inbox"
//
// See if the the username has devices registered. If it has, loop
// over them to find the ones that are interested in the named
// mailbox and send those a push notificiation.
//
// The push notification looks like this:
//
//  { "aps": { "account-id": aps-account-id } }
//

func handleNotify(conn net.Conn, cmd command, client *apns2.Client, db *Database) {
	// Make sure we got the required arguments
	username, ok := cmd.getStringArg("dovecot-username")
	if !ok {
		writeError(conn, "Missing dovecot-username argument")
		return
	}
	mailbox, ok := cmd.getStringArg("dovecot-mailbox")
	if !ok {
		writeError(conn, "Missing dovecot-mailbox argument")
		return
	}

	// Find all the devices registered for this mailbox event
	registrations, err := db.findRegistrations(username, mailbox)
	if err != nil {
		writeError(conn, "Cannot lookup registrations: "+err.Error())
		return
	}

	// Send a notification to all registered devices. We ignore failures
	// because there is not a lot we can do. We do delete registrations
	// if Apple servers respond with 410 error.
	for _, registration := range registrations {
		if *debug {
			log.Println("[DEBUG] Sending notification to", registration.AccountId, "/", registration.DeviceToken)
		}
		res := sendNotification(registration, client)
		if res.StatusCode == 410 {
			if *debug {
				log.Printf("[DEBUG] Device %v (DB: %v) is no longer registered. APN-Status: %v (%v)\n", registration.AccountId, registration.DbId, res.StatusCode, res.Reason)
			}
			db.deleteRegistration(registration)
		}
	}

	writeSuccess(conn, "")
}

func sendNotification(reg Registration, client *apns2.Client) (*apns2.Response) {
	notification := &apns2.Notification{}
	notification.Payload = SetAccountID(reg.AccountId)
	notification.DeviceToken = reg.DeviceToken
	res, err := client.Push(notification)

	if err != nil {
		log.Println("Sending Notification failed: ", err)
		return nil
        }

	if *debug {
		log.Printf("[DEBUG] %v %v %v\n", res.StatusCode, res.ApnsID, res.Reason)
        }
	return res
}

func writeError(conn net.Conn, msg string) {
	if *debug {
		log.Println("[DEBUG] Returning failure:", msg)
	}
	conn.Write([]byte("ERROR" + " " + msg + "\n"))
}

func writeSuccess(conn net.Conn, msg string) {
	if *debug {
		log.Println("[DEBUG] Returning success:", msg)
	}
	conn.Write([]byte("OK" + " " + msg + "\n"))
}
