package main

// 참고 https://covenant.tistory.com/203

// 추가는 go get 주소
import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

type User struct {
	ID       uint64 `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type TokenType struct {
	Token string `json:"token"`
}

var (
	router     = gin.Default()
	savedToken = ""
)

var user = User{
	ID:       1,
	Username: "username",
	Password: "password",
}

func CreateToken(userid uint64) (string, error) {
	var err error
	//Creating Access Token
	os.Setenv("ACCESS_SECRET", "jdnfksdmfksd")
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["user_id"] = userid
	atClaims["exp"] = time.Now().Add(time.Minute * 15).Unix()
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	token, err := at.SignedString([]byte(os.Getenv("ACCESS_SECRET")))
	if err != nil {
		return "", err
	}
	return token, nil
}

func Login(c *gin.Context) {
	var u User

	if err := c.ShouldBindJSON(&u); err != nil {
		c.JSON(http.StatusUnprocessableEntity, "Invalid json provided")
		return
	}

	if user.Username != u.Username || user.Password != u.Password {
		c.JSON(http.StatusUnauthorized, "Please provide valid login details")
		return
	}
	token, err := CreateToken(user.ID)

	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}

	results := TokenType{
		Token: token,
	}

	savedToken = token

	c.JSON(http.StatusOK, results)
}

func CheckToken(c *gin.Context) {
	type Response struct {
		ID       uint64 `json:"id"`
		Username string `json:"userName"`
	}

	token := c.Request.Header.Get("Authorization")
	if token != savedToken {
		c.JSON(http.StatusUnauthorized, "Please provide valid login details")
		return
	}

	results := Response{
		ID:       1,
		Username: "taese0ng",
	}
	c.JSON(http.StatusOK, results)
}

func main() {
	router.Use(cors.New(cors.Config{
		AllowMethods:     []string{"GET", "POST", "OPTIONS", "PUT"},
		AllowHeaders:     []string{"Origin", "Content-Length", "Content-Type", "User-Agent", "Referrer", "Host", "Token", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		AllowAllOrigins:  false,
		AllowOriginFunc:  func(origin string) bool { return true },
		MaxAge:           86400,
	}))
	router.POST("/login", Login)
	router.GET("/check/token", CheckToken)

	log.Fatal(router.Run(":8080"))
}
