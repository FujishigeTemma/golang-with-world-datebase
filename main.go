package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/labstack/echo"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/middleware"
	"github.com/srinathgs/mysqlstore"
	"golang.org/x/crypto/bcrypt"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
)

type City struct {
	ID          int    `json:"id,omitempty"  db:"ID"`
	Name        string `json:"name,omitempty"  db:"Name"`
	CountryCode string `json:"countryCode,omitempty"  db:"CountryCode"`
	District    string `json:"district,omitempty"  db:"District"`
	Population  int    `json:"population,omitempty"  db:"Population"`
}

var (
	db *sqlx.DB
)

func main() {
	_db, err := sqlx.Connect("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8&parseTime=True&loc=Local", os.Getenv("DB_USERNAME"), os.Getenv("DB_PASSWORD"), os.Getenv("DB_HOSTNAME"), os.Getenv("DB_PORT"), os.Getenv("DB_DATABASE")))
	if err != nil {
		log.Fatalf("Cannot Connect to Database: %s", err)
	} //DataBaseに接続してる（エラーならその内容を表示）
	db = _db //func mainの外でも使えるように外で定義したdbに_dbを代入

	store, err := mysqlstore.NewMySQLStoreFromConnection(db.DB, "sessions", "/", 60*60*24*14, []byte("secret-token"))
	if err != nil {
		panic(err)
	} //store, errを上手いことしてくれる　panic=実行をその時点で終了する

	e := echo.New()                  //echoのインスタンス（echo＝サーバーに関するリクエストとかレスポンスとかの情報諸々を処理してくれるライブラリ）
	e.Use(middleware.Logger())       //通行者のlogをとる
	e.Use(session.Middleware(store)) //通行証の正当性を確認したのち、echo.Contextにその情報を追加

	/*e.GET("/ping", func(c echo.Context) error {
		return c.String(http.StatusOK, "pong")
	})*/ //ピンポン

	e.POST("/signup", postSignUpHandler)
	e.POST("/login", postLoginHandler) //こいつらはボタンで分かれてる（ちなみにUseは上から順）

	withLogin := e.Group("") //
	withLogin.Use(checkLogin)
	withLogin.GET("/cities/:cityName", getCityInfoHandler)
	withLogin.GET("/whoami", getWhoAmIHandler)

	e.Start(":11600")
}

type LoginRequestBody struct {
	Username string `json:"username,omitempty" form:"username"` //リクエストのBodyから構造体に上手いこと対応してることを教えてくれる
	Password string `json:"password,omitempty" form:"password"`
} //ログイン情報の定義（リクエストにくっついてる、クライアントからくる）

type User struct {
	Username   string `json:"username,omitempty"  db:"Username"`
	HashedPass string `json:"-"  db:"HashedPass"`
} //ユーザー情報の定義（ログイン情報の検証に使う、DBから持ってくる）

//returnのあとはfuncをぬける
func postSignUpHandler(c echo.Context) error {
	req := LoginRequestBody{}
	c.Bind(&req) //対応するリクエストのKeyの値を構造体にうまくあてはめてくれる

	// もう少し真面目にバリデーションするべき（場合分けがなんとなくガバそう）
	if req.Password == "" || req.Username == "" {
		// エラーは真面目に返すべき
		return c.String(http.StatusBadRequest, "項目が空です")
	}

	hashedPass, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost) //bcryptでpasswordをハッシュ化されたパスワードを生成
	if err != nil {
		return c.String(http.StatusInternalServerError, fmt.Sprintf("bcrypt generate error: %v", err))
	}

	// 作ろうとしているUserNameが既存のものと重複していないかチェック
	var count int

	err = db.Get(&count, "SELECT COUNT(*) FROM users WHERE Username=?", req.Username) //COUNT該当する行数を返す
	if err != nil {
		return c.String(http.StatusInternalServerError, fmt.Sprintf("db error: %v", err))
	}

	if count > 0 {
		return c.String(http.StatusConflict, "ユーザーが既に存在しています")
	}

	//_=返り値が返ってくるけどいらないから明示的に捨てる
	_, err = db.Exec("INSERT INTO users (Username, HashedPass) VALUES (?, ?)", req.Username, hashedPass)
	if err != nil {
		return c.String(http.StatusInternalServerError, fmt.Sprintf("db error: %v", err))
	}
	return c.NoContent(http.StatusCreated)
}

func postLoginHandler(c echo.Context) error {
	req := LoginRequestBody{}
	c.Bind(&req)

	user := User{}
	err := db.Get(&user, "SELECT * FROM users WHERE username=?", req.Username) //リクエストのUserがDBに存在するか問い合わせしていればその情報をUserにその情報を追加
	if err != nil {
		return c.String(http.StatusInternalServerError, fmt.Sprintf("db error: %v", err))
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.HashedPass), []byte(req.Password))
	if err != nil {
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return c.NoContent(http.StatusForbidden) //Passwordの不一致
		} else {
			return c.NoContent(http.StatusInternalServerError)
		}
	}

	sess, err := session.Get("sessions", c) //session（サーバー側に存在する帳簿）にUserを登録
	if err != nil {
		fmt.Println(err)
		return c.String(http.StatusInternalServerError, "something wrong in getting session")
	}
	sess.Values["userName"] = req.Username
	sess.Save(c.Request(), c.Response())

	return c.NoContent(http.StatusOK)
}

func checkLogin(next echo.HandlerFunc) echo.HandlerFunc { //middlewareと呼ばれるRequestとHandler関数をつなぐもの
	return func(c echo.Context) error {
		sess, err := session.Get("sessions", c) //sessionの取得（userNameがその中に存在しているかどうか？）
		if err != nil {
			fmt.Println(err)
			return c.String(http.StatusInternalServerError, "something wrong in getting session")
		}

		if sess.Values["userName"] == nil {
			return c.String(http.StatusForbidden, "please login")
		}
		c.Set("userName", sess.Values["userName"].(string))

		return next(c)
	}
}

func getCityInfoHandler(c echo.Context) error {
	cityName := c.Param("cityName") //Parameterの読み取り

	city := City{} //cityという構造体を定義
	db.Get(&city, "SELECT * FROM city WHERE Name=?", cityName)
	if city.Name == "" {
		return c.NoContent(http.StatusNotFound)
	}

	return c.JSON(http.StatusOK, city)
}

type Me struct {
	Username string `json:"username,omitempty"  db:"username"`
}

func getWhoAmIHandler(c echo.Context) error {
	return c.JSON(http.StatusOK, Me{
		Username: c.Get("userName").(string),
	})
}
