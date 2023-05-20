package main

import (
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"net/http"
	"fmt"
	"io"
	"encoding/json"
	"context"
	"log"
	"encoding/base64"
	"crypto/rand"
	"os"
	"time"
	"html/template"
	"database/sql"
	"github.com/go-redis/redis/v8"
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/net/websocket"
	"strings"
	"github.com/google/uuid"
	"strconv"
)

type Homework struct {
	HWList[] template.HTML
	Repository string
	PDF string
	Score int
	Action string
	Title string
	User string
	Session string
	Host string	//Web server host
}

var (
	googleOauthConfig = &oauth2.Config {
		ClientID: os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		Scopes: []string{"https://www.googleapis.com/auth/userinfo.email"},
		Endpoint: google.Endpoint,
	}
	rdsURI = os.Getenv("REDIS_URI")	//example.com:6379
	sqlURI = os.Getenv("SQL_URI")	//user:password@tcp(example.com:3306)
	rsURI = os.Getenv("REPOSITORY_SERVER_URI")	//http://example.com:8081
	gitPort = os.Getenv("GIT_PORT")	//22
	ctx = context.Background()
)

const oauthGoogleUrlAPI =
	"https://www.googleapis.com/oauth2/v2/userinfo?access_token="

func handleOAuth(w http.ResponseWriter, r *http.Request) {
	// Check scheme
	scheme := r.Header.Get("scheme")
	if scheme != "https" {
		scheme = "http"
	}
	// Check Host
	if r.Header.Get("X-Forwarded-For") != "" {
		googleOauthConfig.RedirectURL = scheme + "://" +
			r.Header.Get("X-Forwarded-For") + "/callback"
	} else {
		googleOauthConfig.RedirectURL = scheme + "://" + r.Host + "/callback"
	}
	// Create oauthState cookie
	oauthState := generateStateOauthCookie(w)

	u := googleOauthConfig.AuthCodeURL(oauthState)
	http.Redirect(w, r, u, http.StatusTemporaryRedirect)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	var (
		userdata map[string] any
		err error
		session *http.Cookie
		rdb = redis.NewClient(&redis.Options{Addr: rdsURI})
		data []byte
	)
	// Read oauthState from cookie
	if oauthState, err := r.Cookie("oauthstate"); err == http.ErrNoCookie {
		goto invsess
	} else if r.FormValue("state") != oauthState.Value {
		goto invsess
	}
	// Get user's email address
	if data, err = getUserDataFromGoogle(r.FormValue("code")); err != nil {
		goto srverr
	} else if err = json.Unmarshal(data, &userdata); err != nil {
		goto srverr
	}
	if session, err = r.Cookie("session"); err == http.ErrNoCookie {
		goto srverr
	}
	// Store session on redis
	// key = session, value = address
	err =
		rdb.Set(ctx, session.Value, userdata["email"], 15 * time.Minute).Err()
	if err == redis.Nil {
		goto invsess
	} else if err != nil {
		goto srverr
	}
	http.Redirect(w, r, "/home", http.StatusTemporaryRedirect)
invsess:	//invalid session
	log.Print("Invalid Session")
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	return
srverr:	//internal server error
	log.Print(err)
	// Return status code 500
	http.Error(w, http.StatusText(500), 500)
	return
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	var (
		key = r.URL.Query().Get("key")
		rdb = redis.NewClient(&redis.Options{Addr: rdsURI})
		tpl *template.Template
		mail string
	)
	// Check session field
	session, err := r.Cookie("session")
	if err != nil {
		goto invsess
	}
	// Check address
	mail, err = rdb.Get(ctx, session.Value).Result()
	if err == redis.Nil || mail == "" || strings.Index(mail, "@") < 0 {
		goto invsess
	} else if err != nil {
		goto srverr
	}
	// Update public key
	if key != "" {
		// Register public key value on redis
		if err = rdb.RPush(ctx, key, mail).Err(); err != nil {
			goto srverr
		}
		req, err := http.NewRequest("POST", rsURI + "/key/" + key, nil)
		if err != nil {
			goto srverr
		}
		client := new(http.Client)
		// Try updating public key and check status code
		if resp, err := client.Do(req); err != nil || resp.StatusCode != 200 {
			goto srverr
		}
	}
	// Insert data in the html source of the template
	if tpl, err = template.ParseFiles("templates/home.html"); err != nil {
		goto srverr
	}
	tpl.Execute(w, mail[:strings.Index(mail, "@")])
	return
invsess:	//invalid session
	log.Print("Invalid Session")
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	return
srverr:	//internal server error
	log.Print(err)
	// Return status code 500
	http.Error(w, http.StatusText(500), 500)
	return
}

func handleSubject(w http.ResponseWriter, r *http.Request) {
	var (
		subject = r.URL.Query().Get("subject")
		homework = r.URL.Query().Get("homework")
		rdb = redis.NewClient(&redis.Options{Addr: rdsURI})
		hw Homework
		score int
		repository sql.NullString
		stmt string
		rowcnt int
		db *sql.DB
		mail string
		tpl *template.Template
		err error
	)
	hw.Action = "Evaluate"
	hw.HWList = make([]template.HTML, 0, 10)
	// Check session field
	if session, err := r.Cookie("session"); err != nil {
		goto invsess
	} else {
		hw.Session = session.Value
	}
	// Check if the session is valid
	mail, err = rdb.Get(ctx, hw.Session).Result()
	if err == redis.Nil || mail == "" {
		goto invsess
	} else if err != nil {
		goto srverr
	} else if strings.Index(mail, "@") < 0 {
		goto badrequest
	}
	hw.User = mail[:strings.Index(mail, "@")]
	// Check X-Forwarded-Host
	hw.Host = r.Header.Get("X-Forwarded-Host")
	if r.Header.Get("X-Forwarded-Host") != "" {
		hw.Host = r.Header.Get("X-Forwarded-For")
	} else {
		hw.Host = r.Host
	}
	// Connect to sql
	if db, err = sql.Open("mysql", sqlURI + "/" + subject); err != nil {
		goto srverr
	}
	defer db.Close()
	// Query homework list
	if result, err := db.Query("show tables"); err != nil {
		goto srverr
	} else {
		for result.Next() {
			var h string
			prefix := "<a href=\"/subject?subject="
			result.Scan(&h)
			h = prefix + subject + "&homework=" + h + "\">" + h + "</a>"
			hw.HWList = append(hw.HWList, template.HTML(h))
		}
	}
	// If no homework is specified in the url parameter,
	// insert data in the html source of the template
	if homework == "" {
		goto ok
	}
	// Check if the user's homework data exists
	stmt = "select count(*) from " + homework + " where email = ?"
	if err = db.QueryRow(stmt, mail).Scan(&rowcnt); err != nil {
		goto srverr
	}
	// Initialize data if the user's homework data doesn't exist
	if rowcnt == 0 {
		stmt = "insert into " + homework +
			"(email, score, repository) values(?, ?, ?)"
		if result, err := db.Exec(stmt, mail, 0, ""); err != nil {
			goto srverr
		} else if _, err = result.LastInsertId(); err != nil {
			goto srverr
		}
	}
	// Set title
	hw.Title = subject + "/" + homework
	// Query score data
	stmt = "select score from " + homework + " where email = ?"
	if err = db.QueryRow(stmt, mail).Scan(&score); err != nil {
		goto srverr
	}
	hw.Score = score
	// Query repository
	stmt = "select repository from " + homework + " where email = ?"
	if err = db.QueryRow(stmt, mail).Scan(&repository); err != nil {
		goto srverr
	}
	// Set repository location
	if hw.Repository = repository.String; hw.Repository == "" {	
		// If the repository has not been created,
		// set the action to "Initialize"
		hw.Action = "Initialize"
	}
	// Get PDF URI
	hw.PDF, err = rdb.Get(ctx, subject + "-" + homework).Result()
	if err != nil {
		goto srverr
	}
ok:
	// Insert data in the html source of the template
	if tpl, err = template.ParseFiles("templates/subject.html"); err != nil {
		goto srverr
	}
	tpl.Execute(w, hw)
	return
invsess:	//invalid session
	log.Print("Invalid Session")
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	return
badrequest:
	// Return status code 400
	http.Error(w, http.StatusText(400), 400)
	return
srverr:	//internal server error
	log.Print(err)
	// Return status code 500
	http.Error(w, http.StatusText(500), 500)
	return
}

func handleGit(ws *websocket.Conn) {
	var (
		rdb = redis.NewClient(&redis.Options{Addr: rdsURI})
		msg string
		session string
		err error
		mail string
		user string
		homework string
		uuidobj uuid.UUID
		host string
		stmt string
		repository string
		req *http.Request
		db *sql.DB
		resp *http.Response
		result sql.Result
	)
	defer ws.Close()
	// Check session
	if err = websocket.Message.Receive(ws, &session); err != nil {
		goto exception
	}
	// Search user by using session
	if mail, err = rdb.Get(ctx, session).Result(); err == redis.Nil ||
		mail == "" || strings.Index(mail, "@") < 0 {
		goto invsess
	} else if err != nil {
		goto exception
	}
	user = mail[:strings.Index(mail, "@")]
	// Send accept message
	if err = websocket.Message.Send(ws, "AcceptedSession"); err != nil {
		goto exception
	}
	// Get homework
	if err = websocket.Message.Receive(ws, &msg); err != nil {
		goto exception
	}
	if strings.Index(msg, "/") < 0 {
		goto exception
	}
	// Connect to sql
	db, err = sql.Open("mysql", sqlURI + "/" + msg[:strings.Index(msg, "/")])
	if err != nil {
		goto exception
	}
	defer db.Close()
	// Get homework
	homework = msg[strings.Index(msg, "/") + 1:]
	// Generate repository name by using uuid version 4
	if uuidobj, err = uuid.NewRandom(); err != nil {
		goto exception
	}
	if err = rdb.RPush(ctx, uuidobj.String(), mail).Err(); err != nil {
		goto exception
	}
	// Generate git repository
	req, err = 
		http.NewRequest("POST", rsURI + "/git/" + uuidobj.String(), nil)
	if err != nil {
		goto exception
	}
	if resp, err = new(http.Client).Do(req); err != nil {
		goto exception
	} else if resp.StatusCode != 200 {
		log.Print(http.StatusText(resp.StatusCode))
		return
	}
	// Register git repository
	if strings.Index(req.Host, ":") < 0 {
		host = req.Host
	} else {
		host = req.Host[:strings.Index(req.Host, ":")]
	}
	repository ="ssh://" + user + "@" + host + ":" +
		gitPort + "/~/" + uuidobj.String() + ".git"
	stmt = "update " + homework + " set repository = ? where email = ?"
	if result, err = db.Exec(stmt, repository, mail); err != nil {
		goto exception
	} else if _, err = result.LastInsertId(); err != nil {
		goto exception
	}
	// Return result
	if err = websocket.Message.Send(ws, repository); err != nil {
		goto exception
	}
	return
invsess:	// Reply failures in creating a git repository
	log.Print("Invalid Session")
	if err = websocket.Message.Send(ws, "Rejected"); err != nil {
		goto exception
	}
	return
exception:
	log.Print(err)
	return
}

func handleEval(ws *websocket.Conn) {
	var (
		rdb = redis.NewClient(&redis.Options{Addr: rdsURI})
		err error
		msg string
		stmt string
		score int
		db *sql.DB
		sub *redis.PubSub
		mail string
	)
	defer ws.Close()
	// Get session
	if err = websocket.Message.Receive(ws, &msg); err != nil {
		goto exception
	}
	// Search user by using session
	if mail, err = rdb.Get(ctx, msg).Result(); err == redis.Nil || mail == "" {
		goto invsess
	} else if err != nil {
		goto exception
	}
	// Send accept message
	if err = websocket.Message.Send(ws, "AcceptedSession"); err != nil {
		goto exception
	}
	// Get homework
	if err = websocket.Message.Receive(ws, &msg); err != nil {
		goto exception
	}
	// Push evalutation job key=subject/homework value=email address
	if err = rdb.RPush(ctx, msg, mail).Err(); err != nil {
		goto exception
	}
	// Subscribe to homework channel to wait for the end of the evaluation 
	sub = rdb.Subscribe(ctx, msg)
	for {
		if addr, err := sub.ReceiveMessage(ctx); err != nil {
			goto exception
		} else if addr.Payload[strings.Index(addr.Payload, ":") + 1:] == mail {
			break
		}
	}
	// Connect to sql
	db, err = sql.Open("mysql", sqlURI + "/" + msg[:strings.Index(msg, "/")])
	if err != nil {
		goto exception
	}
	defer db.Close()
	// Query score
	stmt = "select score from " + msg[strings.Index(msg, "/") + 1:] +
		" where email = ?"
	if err = db.QueryRow(stmt, mail).Scan(&score); err != nil {
		goto exception
	}
	if err = websocket.Message.Send(ws, strconv.Itoa(score)); err != nil {
		goto exception
	}
	return
invsess:
	log.Print("Invalid Session")
	if err = websocket.Message.Send(ws, "Rejected"); err != nil {
		goto exception
	}
	return
exception:
	log.Print(err)
	return
}

func generateStateOauthCookie(w http.ResponseWriter) string {
	// Generate cookie
	expiration := time.Now().Add(15 * time.Minute)
	b:= make([]byte, 256)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	cookie := http.Cookie{Name: "oauthstate", Value: state, Expires: expiration}
	http.SetCookie(w, &cookie)

	return state
}

func getUserDataFromGoogle(code string) ([]byte, error) {
	var contents []byte
	// Exchange converts an authorization code into a token
	token, err := googleOauthConfig.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("Code exchange wrong: %s", err.Error())
	}
	// Get user's email address
	response, err := http.Get(oauthGoogleUrlAPI + token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("Failed to get user info: %s", err.Error())
	}
	defer response.Body.Close()
	if contents, err = io.ReadAll(response.Body); err != nil {
		return nil, fmt.Errorf("Failed to read response: %s", err.Error())
	}
	return contents, nil
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	// Load html template
	tpl, err := template.ParseFiles("templates/index.html")
	if err != nil {
		log.Print(err)
		// Return status code 500
		http.Error(w, http.StatusText(500), 500)
		return
	}
	// Show html
	tpl.Execute(w, nil)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	rdb := redis.NewClient(&redis.Options{Addr: rdsURI})
	// Check session and delete session key
	if session, err := r.Cookie("session"); err == http.ErrNoCookie {
		log.Print(err)
	} else if err = rdb.Del(ctx, session.Value).Err(); err != nil {
		log.Print(err)
	}
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func main() {
	// Start web server
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/logout", handleLogout)
	http.HandleFunc("/oauth", handleOAuth)
	http.HandleFunc("/callback", handleCallback)
	http.HandleFunc("/home", handleHome)
	http.HandleFunc("/subject", handleSubject)
	http.Handle("/git", websocket.Handler(handleGit))
	http.Handle("/eval", websocket.Handler(handleEval))
	log.Print("Serving web server at localhost:8080")
	http.ListenAndServe(":8080", nil)
}