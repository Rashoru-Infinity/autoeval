package main

import (
	"net/http"
	"context"
	"os"
	"os/exec"
	"log"
	"github.com/go-redis/redis/v8"
	"strings"
)

var (
	rdsURI = os.Getenv("REDIS_URI")
	ctx = context.Background()
	sqlURI = os.Getenv("SQL_URI")	//user:password@tcp(example.com:3306)
)

func initRepository(w http.ResponseWriter, r *http.Request) {
	var (
		uuid string
		rdb = redis.NewClient(&redis.Options{Addr: rdsURI})
		err error
		mail string
		user string
		output []byte
		basedir string
	)
	if r.Method != "POST" {
		http.Error(w, http.StatusText(405), 405)
		return
	}
	if strings.Index(r.URL.Path, "/git/") < 0  {
		log.Print("No uuid")
		// Return status code 400
		http.Error(w, http.StatusText(400), 400)
		return
	}
	uuid = r.URL.Path[strings.Index(r.URL.Path, "/git/") + len("/git/"):]
	
	if mail, err = rdb.LPop(ctx, uuid).Result(); err == redis.Nil ||
		mail == "" || strings.Index(mail, "@") < 0{
		log.Print("Invalid request")
		// Return status code 400
		http.Error(w, http.StatusText(400), 400)
		return
	} else if err != nil {
		goto srverr
	}
	user = mail[:strings.Index(mail, "@")]
	// sh -c "cat /etc/passwd | grep $user | wc -l"
	output, err =
		exec.Command("sh", "-c", "cat /etc/passwd | grep " +
		user + " | wc -l").Output()
	if err != nil {
		goto srverr
	}
	basedir = "/home/" + user + "/"
	if string(output) == "0\n" {
		err = exec.Command("useradd", "-d", basedir,
			"-m", "-s", "/usr/bin/git-shell", user).Run()
		if err != nil {
			goto srverr
		}
	}
	// git init --bare /home/$user/$uuid.git
	err = exec.Command("git", "init", "--bare", basedir + uuid + ".git").Run()
	if err != nil {
		goto srverr
	}
	// chmod -R 775 /home/$user/$uuid.git
	err = exec.Command("chmod", "-R", "775", basedir + uuid + ".git").Run()
	if err != nil {
		goto srverr
	}
	// chown -R $user:$user /home/$user/$uuid.git
	err = exec.Command("chown", "-R", user + ":" +
		user, basedir + uuid + ".git").Run()
	if err != nil {
		goto srverr
	}
	http.Error(w, http.StatusText(200), 200)
	return
srverr:
	log.Print(err)
	// Return status code 500
	http.Error(w, http.StatusText(500), 500)
	return
}

func updatePubKey(w http.ResponseWriter, r *http.Request) {
	var (
		pubkey string
		rdb = redis.NewClient(&redis.Options{Addr: rdsURI})
		mail string
		err error
		basedir string
		output []byte
		user string
	)
	if r.Method != "POST" {
		http.Error(w, http.StatusText(405), 405)
		return
	}
	if strings.Index(r.URL.Path, "/key/") < 0 {
		log.Print("No pubkey")
		// Return status code 400
		http.Error(w, http.StatusText(400), 400)
		return
	}
	pubkey = r.URL.Path[strings.Index(r.URL.Path, "/key/") + len("/key/"):]
	mail, err = rdb.LPop(ctx, pubkey).Result()
	if err == redis.Nil || mail == ""{
		log.Print("Invalid Key")
		// Return status code 400
		http.Error(w, http.StatusText(400), 400)
		return
	} else if err != nil {
		goto srverr
	} else if strings.Index(mail, "@") < 0 {
		log.Print("Invalid address")
		// Return status code 400
		http.Error(w, http.StatusText(400), 400)
		return
	}
	user = mail[:strings.Index(mail, "@")]
	// sh -c "cat /etc/passwd | grep $user | wc -l"
	output, err = exec.Command("sh", "-c",
		"cat /etc/passwd | grep " + user + " | wc -l").Output()
	if err != nil {
		goto srverr
	}
	basedir = "/home/" + user + "/"
	// Create the user account if the user doesn't exists
	if string(output) == "0\n" {
		err = exec.Command("useradd", "-d",
			basedir, "-m", "-s", "/usr/bin/git-shell", user).Run()
		if err != nil {
			goto srverr
		}
	}
	// stat /home/$user/.ssh
	err = exec.Command("stat", basedir + ".ssh").Run()
	if err != nil {
		// mkdir -p /home/$User/.ssh
		err = exec.Command("mkdir", "-p", basedir + ".ssh").Run()
		if err != nil {
			goto srverr
		}
		// chmod 700 /home/$user/.ssh
		err = exec.Command("chmod", "700", basedir + ".ssh").Run()
		if err != nil {
			goto srverr
		}
	}
	// sh -c "echo $pubkey > /home/$user/.ssh/authorized_keys"
	err = exec.Command("sh", "-c", "echo " + pubkey +
		" > " + basedir + ".ssh/authorized_keys").Run()
	if err != nil {
		goto srverr
	}
	// chmod 600 /home/$user/.ssh/authorized_keys
	err = exec.Command("chmod", "600", basedir + ".ssh/authorized_keys").Run()
	if err != nil {
		goto srverr
	}
	// chown -R $user:$user /home/$user/.ssh
	err = exec.Command("chown", "-R", user +
		":" + user, basedir + ".ssh").Run()
	if err != nil {
		goto srverr
	}
	http.Error(w, http.StatusText(200), 200)
	return
srverr:
	log.Print(err)
	// Return status code 500
	http.Error(w, http.StatusText(500), 500)
	return
}

func main() {
	// Start web server
	mux := http.NewServeMux()
	mux.Handle("/git/", http.HandlerFunc(initRepository))
	mux.Handle("/key/", http.HandlerFunc(updatePubKey))
	log.Print("Serving web server at localhost:8081")
	http.ListenAndServe(":8081", mux)
}