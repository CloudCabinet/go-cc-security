package security

import (
	"os"
	"github.com/dgrijalva/jwt-go"
)
type User struct {
	User_id string `json:"user_id"`
	Group_id string `json:"group_id"`
	Roles map[string]bool `json:"roles"`
	Attr map[string]string `json:"attr"`
	JWT_Key string
	Locale string
	Exp int `json:"exp"`
	Nbf int `json:"nbf"`
	jwt.StandardClaims
}
const header_key  = "authorization"
type _config struct{
	secret_key string
}
var config _config

func getOS(keyos string,def string) string {
	value,err:=os.LookupEnv(keyos)
	if(err){
		return value
	}else{
		return def
	}
}
func init() {
	config.secret_key=getOS("LOGIN_JWT_SECRET_KEY","qwerty")
}