package valid

import (
	"unicode"

	"github.com/go-playground/validator/v10"
)

func ValidatorPassword(fl validator.FieldLevel) bool {
	password := fl.Field().String()
	var UpperSymbol bool
	var LowerSymbol bool
	var NumericSymbol bool
	var SpecificSymbol bool
	var LenPassword bool
	if len(password) > 7 && len(password) < 21 {
		LenPassword = true
	}

	for _, i := range password {

		if unicode.IsUpper(i) {
			UpperSymbol = true
		}
		if unicode.IsLower(i) {
			LowerSymbol = true
		}
		if unicode.IsNumber(i) {
			NumericSymbol = true
		}
		if unicode.IsPunct(i) || unicode.IsSymbol(i) {
			SpecificSymbol = true
		}
	}
	return UpperSymbol && LowerSymbol && NumericSymbol && SpecificSymbol && LenPassword
}
