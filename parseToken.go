package security

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
	"errors"
	"time"
)

func (t User) IsRole(role string) bool {
	if _, ok := t.Roles[role]; ok {
		return true
	}else{
		if _, ok := t.Roles["ROLE_SUPER_USER"]; ok {
			return true
		}else{
			return false
		}

	}
}
func (t User) IsRolePanic(role string) {
	if !t.IsRole(role) {
		panic(errors.New("Access denied role"))
	}
}
var userDev User
func GetUser(tokenString string) User{
	token, err := jwt.ParseWithClaims(tokenString, &User{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(config.secret_key), nil
	})
	if(err!=nil){
		panic(err)
	}
	if user, ok := token.Claims.(*User); ok && token.Valid {
		user.JWT_Key = tokenString

		return *user
	}
	panic(errors.New("Error token user"))

}
func SetUserDev(user User)  {
	userDev = user
	userDev.JWT_Key = createJWT_DEV(user)
}
func GinAuthHandlerDev() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func () {
			if r := recover(); r != nil {
				c.JSON(http.StatusBadRequest, gin.H{})
				c.Abort()
			}
		}()
		c.Set("User", userDev)
		c.Next()
	}
}

func GinAuthHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func () {
			if r := recover(); r != nil {
				c.JSON(http.StatusBadRequest, gin.H{})
				c.Abort()
			}
		}()
		tokenString := c.GetHeader(header_key)
		if len(tokenString) >= 1 {
			tokenString = strings.TrimPrefix(tokenString, "Bearer ")
			user := GetUser(tokenString)
			user.Locale = c.GetHeader("locale")
			c.Set("User", user)
			c.Next()
		}else{
			c.JSON(http.StatusBadRequest, gin.H{})
			c.Abort()
			return
		}

	}
}

func createJWT_DEV (user User) string{
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"group_id": user.Group_id,
		"user_id": user.User_id,
		"roles": user.Roles,
		"attr": user.Attr,
		"exp": time.Now().Add(time.Hour * 12).Unix(),
		"nbf": time.Now().Unix(),
	})
	tokenString, err := token.SignedString([]byte(config.secret_key))
	if(err!=nil){
		panic(err)
	}
	return tokenString;
}
