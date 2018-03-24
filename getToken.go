package security

import (
	"fmt"
)

func (t User) GetToken() string {
	return fmt.Sprintf("Bearer %v", t.JWT_Key)
}
