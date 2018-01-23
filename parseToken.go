package security

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
)

func (t User) IsRole(role string) bool {
	if _, ok := t.Roles[role]; ok {
		return true
	}else{
		return false
	}
}
func GinAuthHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader(header_key)
		if len(tokenString) >= 1 {
			tokenString = strings.TrimPrefix(tokenString, "Bearer ")
			token, err := jwt.ParseWithClaims(tokenString, &User{}, func(token *jwt.Token) (interface{}, error) {
				return []byte(config.secret_key), nil
			})
			if(err!=nil){
				c.JSON(http.StatusBadRequest, gin.H{})
				c.Abort()
				return
			}
			if user, ok := token.Claims.(*User); ok && token.Valid {
				user.JWT_Key = tokenString
				user.Locale = c.GetHeader("locale")
				c.Set("User", user)
				c.Next()
			}
		}else{
			c.JSON(http.StatusBadRequest, gin.H{})
			c.Abort()
			return
		}

	}
}
