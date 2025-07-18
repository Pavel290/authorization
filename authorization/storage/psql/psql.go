package psql

import (
	token "blogV2_REST-API/authorization/Token"
	"blogV2_REST-API/authorization/coockie"
	"blogV2_REST-API/authorization/valid"
	"errors"
	"fmt"
	"log"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type UserAuth struct {
	gorm.Model
	ID       uint   `gorm:"primaryKey"`
	UserName string `gorm:"type:text" json:"username" validate:"required,min=7,max=21"`
	Password string `gorm:"type:text" json:"password" validate:"password"`
}

var DB = ConectDB()

func ConectDB() *gorm.DB {
	dsn := "host=localhost user= password= dbname= port=5432 sslmode=disable"
	db, errOpenDb := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	db.AutoMigrate(&UserAuth{})
	if errOpenDb != nil {
		log.Fatal("не вышло подключиться к БД %w", errOpenDb)
	}
	return db
}

func AddUser(db *gorm.DB, UserName, pass string) error {
	var existingUser UserAuth
	if err := db.Where("user_name = ?", UserName).First(&existingUser).Error; err == nil {
		return fmt.Errorf("пользователь с именем %s уже существует", UserName)
	}
	user := UserAuth{UserName: UserName, Password: pass}

	v := validator.New()
	v.RegisterValidation("password", valid.ValidatorPassword)

	if errValidate := v.Struct(user); errValidate != nil {

		return errors.New("пароль должен содержать от 8 до 20 символов, большие и маленькие буквы, цифры и специальные символы")
	}

	id := LastId(DB) + 1
	ps := []byte(pass)
	hash, errHash := bcrypt.GenerateFromPassword(ps, 10)
	user.Password = string(hash)
	user.ID = id
	if errHash != nil {
		log.Fatalln("не удалось сгенерировать хеш пароля: %w ", errHash)
	}

	if Error := DB.Create(&user).Error; Error != nil {
		return fmt.Errorf("не удалось добавить пользователя в БД: %w", Error)
	}

	return nil
}

func LastId(db *gorm.DB) uint {
	var lastUser UserAuth
	result := db.Order("id DESC").First(&lastUser)
	if result.Error != nil {
		log.Fatal("ошибка получения последней записи: %w", result.Error)
	}
	return lastUser.ID
}

func FindeUser(db *gorm.DB, userID uint) (bool, string, error) {
	var user UserAuth

	if result := db.Take(&user, "id = ?", userID); result.RowsAffected == 1 {
		return true, user.UserName, nil
	} else {
		if result.Error == gorm.ErrRecordNotFound || result.RowsAffected == 0 {
			return false, "", errors.New("пользователь не найден")
		} else if result.Error != nil {
			return false, "", errors.New(fmt.Sprintf("Ошибка при поиске пользователя: %w", result.Error))
		}
	}
	return false, "", errors.New("ошибка при поиске пользователя: %w")
}

func SignIn(db *gorm.DB, username, password string, ctx *gin.Context) (bool, error) {
	var user UserAuth

	if res := db.Take(&user, "user_name = ?", username); res.RowsAffected == 1 {
		if username == user.UserName && bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)) == nil {
			t, errToken := token.CreateJWT(user.UserName, user.Password, user.ID)
			if errToken != nil {
				return false, fmt.Errorf("не удалось зарегистрировать пользователя: %w")
			}

			coockie.SetCookie(ctx, user.UserName, t, user.ID)
			return true, nil
		} else if bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)) != nil {
			return false, fmt.Errorf("не верный пароль")
		} else {
			return false, fmt.Errorf("ошибка при входе в аккаунт: %w", res.Error)
		}
	}
	return false, fmt.Errorf("пользователь не найден")
}
