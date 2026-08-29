// SSH Honeypot
//
// Accepts SSH connections and password login attempts, but never lets
// anyone actually in. Every attempt is logged as a single-line JSON
// object to honeypot.log, which is what Filebeat will later tail and
// ship to Elasticsearch.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/gliderlabs/ssh"
	"github.com/oschwald/geoip2-golang"
)

// LoginAttempt is the structure written to the log for every attempt.
// Keeping this as a plain flat JSON object (rather than nesting) makes
// Filebeat/Elasticsearch field mapping simpler later on. Geo fields are
// pointers so they're omitted from the JSON entirely (rather than
// showing up as zero-value junk) when a lookup isn't available.
type LoginAttempt struct {
	Timestamp time.Time `json:"timestamp"`
	IPAddress string    `json:"ip_address"`
	Username  string    `json:"username"`
	Password  string    `json:"password"`
	Country   string    `json:"country,omitempty"`
	City      string    `json:"city,omitempty"`
	Latitude  float64   `json:"latitude,omitempty"`
	Longitude float64   `json:"longitude,omitempty"`
}

var (
	logFile   *os.File
	geoReader *geoip2.Reader // nil if no GeoIP database was loaded
)

// geoLookup fills in the country/city/lat/lon fields on attempt using
// the loaded MaxMind database. If no database was loaded, or the
// lookup fails (e.g. private/reserved IPs like 127.0.0.1 have no geo
// data), the attempt is left with empty geo fields rather than
// erroring out — a honeypot should never crash because of a lookup
// miss.
func geoLookup(attempt *LoginAttempt, ipStr string) {
	if geoReader == nil {
		return
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return
	}

	record, err := geoReader.City(ip)
	if err != nil {
		// Expect this for local/private IPs during testing; not worth
		// logging loudly for every miss in production.
		return
	}

	attempt.Country = record.Country.Names["en"]
	attempt.City = record.City.Names["en"]
	attempt.Latitude = record.Location.Latitude
	attempt.Longitude = record.Location.Longitude
}

// passwordHandler is called by the ssh server for every password-auth
// attempt. Returning false always fails the login, which is the entire
// point of a honeypot: nobody ever actually gets in, but we learn what
// they tried.
func passwordHandler(ctx ssh.Context, password string) bool {
	ip := remoteIP(ctx)

	attempt := LoginAttempt{
		Timestamp: time.Now().UTC(),
		IPAddress: ip,
		Username:  ctx.User(),
		Password:  password,
	}
	geoLookup(&attempt, ip)

	logAttempt(attempt)

	return false
}

// remoteIP extracts just the IP (dropping the ephemeral source port)
// from the connection's remote address.
func remoteIP(ctx ssh.Context) string {
	host, _, err := net.SplitHostPort(ctx.RemoteAddr().String())
	if err != nil {
		return ctx.RemoteAddr().String()
	}
	return host
}

// logAttempt writes the attempt as a single line of JSON to the log
// file and also echoes a human-readable line to stdout so you can
// watch attempts arrive in real time.
func logAttempt(attempt LoginAttempt) {
	data, err := json.Marshal(attempt)
	if err != nil {
		log.Printf("failed to marshal login attempt: %v", err)
		return
	}

	if _, err := fmt.Fprintln(logFile, string(data)); err != nil {
		log.Printf("failed to write to log file: %v", err)
	}

	location := ""
	if attempt.Country != "" {
		location = fmt.Sprintf(" (%s, %s)", attempt.City, attempt.Country)
	}

	fmt.Printf("[%s] %s%s tried %q / %q\n",
		attempt.Timestamp.Format(time.RFC3339),
		attempt.IPAddress,
		location,
		attempt.Username,
		attempt.Password,
	)
}

func main() {
	port := os.Getenv("HONEYPOT_PORT")
	if port == "" {
		port = "2222"
	}

	logPath := os.Getenv("HONEYPOT_LOG_PATH")
	if logPath == "" {
		logPath = "honeypot.log"
	}

	var err error
	logFile, err = os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("failed to open log file %q: %v", logPath, err)
	}
	defer logFile.Close()

	geoDBPath := os.Getenv("GEOIP_DB_PATH")
	if geoDBPath == "" {
		geoDBPath = "GeoLite2-City.mmdb"
	}
	geoReader, err = geoip2.Open(geoDBPath)
	if err != nil {
		log.Printf("warning: could not load GeoIP database at %q (%v) — continuing without geo enrichment", geoDBPath, err)
		geoReader = nil
	} else {
		defer geoReader.Close()
		log.Printf("GeoIP database loaded from %s", geoDBPath)
	}

	server := &ssh.Server{
		Addr:            ":" + port,
		PasswordHandler: passwordHandler,
	}

	log.Printf("SSH honeypot listening on port %s, logging to %s", port, logPath)
	log.Fatal(server.ListenAndServe())
}