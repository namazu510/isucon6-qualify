package main

import (
	"context"
	"crypto/sha1"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"html/template"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/patrickmn/go-cache"
	"time"

	"github.com/Songmu/strrand"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/unrolled/render"
	"sync"
)

const (
	sessionName   = "isuda_session"
	sessionSecret = "tonymoris"
)

var (
	isutarEndpoint string
	isupamEndpoint string

	baseUrl         *url.URL
	db              *sql.DB
	re              *render.Render
	reIsutar        *render.Render
	store           *sessions.CookieStore
	contentCache    *cache.Cache
	userCache       map[string]*User
	userCacheLock   sync.RWMutex
	replacer1       *strings.Replacer
	replacer2       *strings.Replacer
	replaceList1    []string
	replaceList2    []string
	replaceListLock sync.RWMutex
	errInvalidUser  = errors.New("Invalid User")
)

// key is userID or userName
func getUser(key string) (*User, bool) {
	userCacheLock.RLock()
	user, found := userCache[key]
	userCacheLock.RUnlock()
	if found {
		return user, true
	}
	return nil, false
}

func loadUsers() {
	rows, err := db.Query(`SELECT * FROM user`)
	panicIf(err)
	for rows.Next() {
		user := &User{}
		rows.Scan(&user.ID, &user.Name, &user.Salt, &user.Password, &user.CreatedAt)
		userCacheLock.Lock()
		userCache[strconv.Itoa(user.ID)] = user
		userCache[user.Name] = user
		userCacheLock.Unlock()
	}
}

func setName(w http.ResponseWriter, r *http.Request) error {
	session := getSession(w, r)
	userID, ok := session.Values["user_id"]
	if !ok {
		return nil
	}
	setContext(r, "user_id", userID)

	user, found := getUser(strconv.Itoa(userID.(int)))
	if !found {
		return errInvalidUser
	}
	setContext(r, "user_name", user.Name)
	return nil
}

func authenticate(w http.ResponseWriter, r *http.Request) error {
	if u := getContext(r, "user_id"); u != nil {
		return nil
	}
	return errInvalidUser
}

func initializeIsudaHandler(w http.ResponseWriter, r *http.Request) {
	_, err := db.Exec(`DELETE FROM entry WHERE id > 7101`)
	panicIf(err)
	initReplaceList()

	_, err = db.Exec("TRUNCATE star")
	panicIf(err)

	re.JSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

func topHandler(w http.ResponseWriter, r *http.Request) {
	if err := setName(w, r); err != nil {
		forbidden(w)
		return
	}

	perPage := 10
	p := r.URL.Query().Get("page")
	if p == "" {
		p = "1"
	}
	page, _ := strconv.Atoi(p)

	rows, err := db.Query(fmt.Sprintf(
		"SELECT * FROM entry ORDER BY updated_at DESC LIMIT %d OFFSET %d",
		perPage, perPage*(page-1),
	))
	if err != nil && err != sql.ErrNoRows {
		panicIf(err)
	}
	entries := make([]*Entry, 0, 10)
	for rows.Next() {
		e := Entry{}
		err := rows.Scan(&e.ID, &e.AuthorID, &e.Keyword, &e.Description, &e.UpdatedAt, &e.CreatedAt)
		panicIf(err)
		e.Html = htmlify(w, r, e.Description)
		e.Stars = getStars(e.Keyword)
		entries = append(entries, &e)
	}
	rows.Close()

	var totalEntries int
	row := db.QueryRow(`SELECT COUNT(*) FROM entry`)
	err = row.Scan(&totalEntries)
	if err != nil && err != sql.ErrNoRows {
		panicIf(err)
	}

	lastPage := int(math.Ceil(float64(totalEntries) / float64(perPage)))
	pages := make([]int, 0, 10)
	start := int(math.Max(float64(1), float64(page-5)))
	end := int(math.Min(float64(lastPage), float64(page+5)))
	for i := start; i <= end; i++ {
		pages = append(pages, i)
	}

	re.HTML(w, http.StatusOK, "index", struct {
		Context  context.Context
		Entries  []*Entry
		Page     int
		LastPage int
		Pages    []int
	}{
		r.Context(), entries, page, lastPage, pages,
	})
}

func robotsHandler(w http.ResponseWriter, r *http.Request) {
	notFound(w)
}

func keywordPostHandler(w http.ResponseWriter, r *http.Request) {
	if err := setName(w, r); err != nil {
		forbidden(w)
		return
	}
	if err := authenticate(w, r); err != nil {
		forbidden(w)
		return
	}

	keyword := r.FormValue("keyword")
	if keyword == "" {
		badRequest(w)
		return
	}
	userID := getContext(r, "user_id").(int)
	description := r.FormValue("description")

	if isSpamContents(description) || isSpamContents(keyword) {
		http.Error(w, "SPAM!", http.StatusBadRequest)
		return
	}
	_, err := db.Exec(`
		INSERT INTO entry (author_id, keyword, description, created_at, updated_at)
		VALUES (?, ?, ?, NOW(), NOW())
		ON DUPLICATE KEY UPDATE
		author_id = ?, keyword = ?, description = ?, updated_at = NOW()
	`, userID, keyword, description, userID, keyword, description)
	panicIf(err)
	addKeyword(keyword)
	http.Redirect(w, r, "/", http.StatusFound)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if err := setName(w, r); err != nil {
		forbidden(w)
		return
	}

	re.HTML(w, http.StatusOK, "authenticate", struct {
		Context context.Context
		Action  string
	}{
		r.Context(), "login",
	})
}

func loginPostHandler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	user, found := getUser(name)
	if !found {
		forbidden(w)
		return
	}
	if user.Password != fmt.Sprintf("%x", sha1.Sum([]byte(user.Salt+r.FormValue("password")))) {
		forbidden(w)
		return
	}
	session := getSession(w, r)
	session.Values["user_id"] = user.ID
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusFound)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session := getSession(w, r)
	session.Options = &sessions.Options{MaxAge: -1}
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusFound)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if err := setName(w, r); err != nil {
		forbidden(w)
		return
	}

	re.HTML(w, http.StatusOK, "authenticate", struct {
		Context context.Context
		Action  string
	}{
		r.Context(), "register",
	})
}

func registerPostHandler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	pw := r.FormValue("password")
	if name == "" || pw == "" {
		badRequest(w)
		return
	}
	userID := register(name, pw)
	session := getSession(w, r)
	session.Values["user_id"] = userID
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusFound)
}

func register(user string, pass string) int64 {
	salt, err := strrand.RandomString(`....................`)
	encpass := fmt.Sprintf("%x", sha1.Sum([]byte(salt+pass)))
	now := time.Now()
	panicIf(err)
	res, err := db.Exec(`INSERT INTO user (name, salt, password, created_at) VALUES (?, ?, ?, ?)`,
		user, salt, encpass, now)
	panicIf(err)
	lastInsertID, _ := res.LastInsertId()
	id := int(lastInsertID)

	u := &User{
		ID:        id,
		Name:      user,
		Salt:      salt,
		Password:  encpass,
		CreatedAt: now,
	}
	userCacheLock.Lock()
	userCache[strconv.Itoa(id)] = u
	userCache[user] = u
	userCacheLock.Unlock()
	return lastInsertID
}

func keywordByKeywordHandler(w http.ResponseWriter, r *http.Request) {
	if err := setName(w, r); err != nil {
		forbidden(w)
		return
	}

	keyword := mux.Vars(r)["keyword"]
	keyword, err := url.QueryUnescape(keyword)
	if err != nil {
		badRequest(w)
		return
	}
	row := db.QueryRow(`SELECT * FROM entry WHERE keyword = ?`, keyword)
	e := Entry{}
	err = row.Scan(&e.ID, &e.AuthorID, &e.Keyword, &e.Description, &e.UpdatedAt, &e.CreatedAt)
	if err == sql.ErrNoRows {
		notFound(w)
		return
	}
	e.Html = htmlify(w, r, e.Description)
	e.Stars = getStars(e.Keyword)

	re.HTML(w, http.StatusOK, "keyword", struct {
		Context context.Context
		Entry   Entry
	}{
		r.Context(), e,
	})
}

func keywordByKeywordDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if err := setName(w, r); err != nil {
		forbidden(w)
		return
	}
	if err := authenticate(w, r); err != nil {
		forbidden(w)
		return
	}

	keyword := mux.Vars(r)["keyword"]
	keyword, err := url.QueryUnescape(keyword)
	if err != nil {
		badRequest(w)
		return
	}
	if keyword == "" {
		badRequest(w)
		return
	}
	if r.FormValue("delete") == "" {
		badRequest(w)
		return
	}
	row := db.QueryRow(`SELECT * FROM entry WHERE keyword = ?`, keyword)
	e := Entry{}
	err = row.Scan(&e.ID, &e.AuthorID, &e.Keyword, &e.Description, &e.UpdatedAt, &e.CreatedAt)
	if err == sql.ErrNoRows {
		notFound(w)
		return
	}
	_, err = db.Exec(`DELETE FROM entry WHERE keyword = ?`, keyword)
	panicIf(err)
	deleteKeyword(keyword)
	http.Redirect(w, r, "/", http.StatusFound)
}

func getStars(keyword string) []*Star {
	stars := make([]*Star, 0, 10)

	rows, err := db.Query(`SELECT * FROM star WHERE keyword = ?`, keyword)
	if err != nil && err != sql.ErrNoRows {
		panicIf(err)
		return stars
	}

	for rows.Next() {
		s := &Star{}
		err := rows.Scan(&s.ID, &s.Keyword, &s.UserName, &s.CreatedAt)
		panicIf(err)
		stars = append(stars, s)
	}
	rows.Close()
	return stars
}

func setStars(keyword, user string) {
	_, err := db.Exec(`INSERT INTO star (keyword, user_name, created_at) VALUES (?, ?, NOW())`, keyword, user)
	panicIf(err)
}

func starsHandler(w http.ResponseWriter, r *http.Request) {
	keyword := r.FormValue("keyword")
	stars := getStars(keyword)

	reIsutar.JSON(w, http.StatusOK, map[string][]*Star{
		"result": stars,
	})
}

func starsPostHandler(w http.ResponseWriter, r *http.Request) {
	keyword := r.FormValue("keyword")
	user := r.FormValue("user")
	origin := os.Getenv("ISUDA_ORIGIN")
	if origin == "" {
		origin = "http://localhost:5000"
	}

	rows, err := db.Query(`SELECT * FROM entry WHERE keyword = ?`, keyword)
	if err != nil && err != sql.ErrNoRows {
		panic(err)
	}
	if !rows.Next() {
		// キーワードが存在しない場合は、404を返す
		notFound(w)
		rows.Close()
		return
	}
	rows.Close()
	setStars(keyword, user)
	reIsutar.JSON(w, http.StatusOK, map[string]string{"result": "ok"})

}

func fetchKeywordReplacer() (*strings.Replacer, *strings.Replacer) {
	replaceListLock.RLock()
	defer replaceListLock.RUnlock()
	return replacer1, replacer2
}

func initReplaceList() {
	rows, err := db.Query(`
		SELECT keyword FROM entry ORDER BY CHARACTER_LENGTH(keyword) DESC
	`)
	panicIf(err)
	entries := make([]*Entry, 0, 8000)
	for rows.Next() {
		e := Entry{}
		err := rows.Scan(&e.Keyword)
		panicIf(err)
		entries = append(entries, &e)
	}
	rows.Close()

	keywords := make([]string, 0, 8000)
	for _, entry := range entries {
		keywords = append(keywords, regexp.QuoteMeta(entry.Keyword))
	}

	replaceListLock.Lock()
	replaceList1 = make([]string, 0, 8000)
	kw2sha := make(map[string]string)
	for _, keyword := range keywords {
		hashKey := "isuda_" + fmt.Sprintf("%x", sha1.Sum([]byte(keyword)))
		kw2sha[keyword] = hashKey
		replaceList1 = append(replaceList1, keyword)
		replaceList1 = append(replaceList1, hashKey)
	}

	replaceList2 = make([]string, 0, 8000)
	for kw, hash := range kw2sha {
		u, err := baseUrl.Parse(baseUrl.String() + "/keyword/" + pathURIEscape(kw))
		panicIf(err)
		link := fmt.Sprintf("<a href=\"%s\">%s</a>", u, html.EscapeString(kw))
		replaceList2 = append(replaceList2, hash)
		replaceList2 = append(replaceList2, link)
	}
	replaceList2 = append(replaceList2, "\n")
	replaceList2 = append(replaceList2, "<br />\n")
	resetKeywordReplacer()
	replaceListLock.Unlock()
}

func addKeyword(keyword string) {
	hash := "isuda_" + fmt.Sprintf("%x", sha1.Sum([]byte(keyword)))
	u, err := baseUrl.Parse(baseUrl.String() + "/keyword/" + pathURIEscape(keyword))
	panicIf(err)
	link := fmt.Sprintf("<a href=\"%s\">%s</a>", u, html.EscapeString(keyword))

	replaceListLock.Lock()
	replaceList1 = append(replaceList1, keyword, hash)
	replaceList2[len(replaceList2)-2] = hash
	replaceList2[len(replaceList2)-1] = link
	replaceList2 = append(replaceList2, "\n", "<br />\n")
	resetKeywordReplacer()
	replaceListLock.Unlock()
}

func deleteKeyword(keyword string) {
	replaceListLock.Lock()
	for i := 0; i < len(replaceList1); i += 2 {
		if replaceList1[i] == keyword {
			// remove replaceList1[i], replaceList1[i+1]
			for j := i + 2; j < len(replaceList1); j++ {
				replaceList1[j-2] = replaceList1[j]
			}
			replaceList1 = replaceList1[:len(replaceList1)-2]

			// remove replaceList2[i], replaceList2[i+1]
			for j := i + 2; j < len(replaceList2); j++ {
				replaceList2[j-2] = replaceList2[j]
			}
			replaceList2 = replaceList2[:len(replaceList2)-2]
			break
		}
	}
	resetKeywordReplacer()
	replaceListLock.Unlock()
}

func resetKeywordReplacer() {
	replacer1 = strings.NewReplacer(replaceList1...)
	replacer2 = strings.NewReplacer(replaceList2...)
	contentCache.Flush()
}

func htmlify(w http.ResponseWriter, r *http.Request, content string) string {
	if content == "" {
		return ""
	}
	origContent := content

	cnt, found := contentCache.Get(content)
	if found {
		return cnt.(string)
	}

	re, re2 := fetchKeywordReplacer()
	content = re.Replace(content)
	content = html.EscapeString(content)
	content = re2.Replace(content)
	contentCache.Set(origContent, content, cache.DefaultExpiration)

	return content
}

func isSpamContents(content string) bool {
	v := url.Values{}
	v.Set("content", content)
	resp, err := http.PostForm(isupamEndpoint, v)
	panicIf(err)
	defer resp.Body.Close()

	var data struct {
		Valid bool `json:valid`
	}
	err = json.NewDecoder(resp.Body).Decode(&data)
	panicIf(err)
	return !data.Valid
}

func getContext(r *http.Request, key interface{}) interface{} {
	return r.Context().Value(key)
}

func setContext(r *http.Request, key, val interface{}) {
	if val == nil {
		return
	}

	r2 := r.WithContext(context.WithValue(r.Context(), key, val))
	*r = *r2
}

func getSession(w http.ResponseWriter, r *http.Request) *sessions.Session {
	session, _ := store.Get(r, sessionName)
	return session
}

func main() {
	host := os.Getenv("ISUDA_DB_HOST")
	if host == "" {
		host = "localhost"
	}
	portstr := os.Getenv("ISUDA_DB_PORT")
	if portstr == "" {
		portstr = "3306"
	}
	port, err := strconv.Atoi(portstr)
	if err != nil {
		log.Fatalf("Failed to read DB port number from an environment variable ISUDA_DB_PORT.\nError: %s", err.Error())
	}
	user := os.Getenv("ISUDA_DB_USER")
	if user == "" {
		user = "isucon"
	}
	password := os.Getenv("ISUDA_DB_PASSWORD")
	if password == "" {
		password = "isucon"
	}
	dbname := os.Getenv("ISUDA_DB_NAME")
	if dbname == "" {
		dbname = "isuda"
	}

	db, err = sql.Open("mysql", fmt.Sprintf(
		"%s:%s@tcp(%s:%d)/%s?loc=Local&parseTime=true",
		user, password, host, port, dbname,
	))
	if err != nil {
		log.Fatalf("Failed to connect to DB: %s.", err.Error())
	}
	db.Exec("SET SESSION sql_mode='TRADITIONAL,NO_AUTO_VALUE_ON_ZERO,ONLY_FULL_GROUP_BY'")
	db.Exec("SET NAMES utf8mb4")

	isutarEndpoint = os.Getenv("ISUTAR_ORIGIN")
	if isutarEndpoint == "" {
		isutarEndpoint = "http://localhost:5001"
	}
	isupamEndpoint = os.Getenv("ISUPAM_ORIGIN")
	if isupamEndpoint == "" {
		isupamEndpoint = "http://localhost:5050"
	}

	store = sessions.NewCookieStore([]byte(sessionSecret))

	// cache create
	contentCache = cache.New(2*time.Minute, 2*time.Minute)
	userCache = map[string]*User{}
	loadUsers()

	re = render.New(render.Options{
		Directory: "views",
		Funcs: []template.FuncMap{
			{
				"url_for": func(path string) string {
					return baseUrl.String() + path
				},
				"title": func(s string) string {
					return strings.Title(s)
				},
				"raw": func(text string) template.HTML {
					return template.HTML(text)
				},
				"add": func(a, b int) int {
					return a + b
				},
				"sub": func(a, b int) int {
					return a - b
				},
				"entry_with_ctx": func(entry Entry, ctx context.Context) *EntryWithCtx {
					return &EntryWithCtx{Context: ctx, Entry: entry}
				},
			},
		},
	})
	reIsutar = render.New(render.Options{Directory: "dummy"})

	r := mux.NewRouter()
	r.UseEncodedPath()
	r.HandleFunc("/", myHandler(topHandler))
	r.HandleFunc("/initialize", myHandler(initializeIsudaHandler)).Methods("GET")
	r.HandleFunc("/robots.txt", myHandler(robotsHandler))
	r.HandleFunc("/keyword", myHandler(keywordPostHandler)).Methods("POST")

	l := r.PathPrefix("/login").Subrouter()
	l.Methods("GET").HandlerFunc(myHandler(loginHandler))
	l.Methods("POST").HandlerFunc(myHandler(loginPostHandler))
	r.HandleFunc("/logout", myHandler(logoutHandler))

	g := r.PathPrefix("/register").Subrouter()
	g.Methods("GET").HandlerFunc(myHandler(registerHandler))
	g.Methods("POST").HandlerFunc(myHandler(registerPostHandler))

	k := r.PathPrefix("/keyword/{keyword}").Subrouter()
	k.Methods("GET").HandlerFunc(myHandler(keywordByKeywordHandler))
	k.Methods("POST").HandlerFunc(myHandler(keywordByKeywordDeleteHandler))

	s := r.PathPrefix("/stars").Subrouter()
	s.Methods("GET").HandlerFunc(myHandler(starsHandler))
	s.Methods("POST").HandlerFunc(myHandler(starsPostHandler))

	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./public/")))
	log.Fatal(http.ListenAndServe(":5000", r))
}
