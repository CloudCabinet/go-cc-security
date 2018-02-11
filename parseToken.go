package security

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
	"errors"
)

func (t User) IsRole(role string) bool {
	if _, ok := t.Roles[role]; ok {
		return true
	}else{
		return false
	}
}
func GetUser(tokenString string) *User{
	token, err := jwt.ParseWithClaims(tokenString, &User{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(config.secret_key), nil
	})
	if(err!=nil){
		panic(err)
	}
	if user, ok := token.Claims.(*User); ok && token.Valid {
		user.JWT_Key = tokenString

		return user
	}
	panic(errors.New("Error token user"))

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
