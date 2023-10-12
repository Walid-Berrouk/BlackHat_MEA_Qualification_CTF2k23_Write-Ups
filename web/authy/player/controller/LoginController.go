package controllers

import (
	"encoding/json"
	"io"
	"net/http"
	"os"

	"github.com/blackhat/db"
	"github.com/blackhat/helper"
	models "github.com/blackhat/model"
	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/log"
	"golang.org/x/crypto/bcrypt"
)

func Registration(c echo.Context) error {
	var user models.Users
	body, _ := io.ReadAll(c.Request().Body)
	err := json.Unmarshal(body, &user)
	if err != nil {
		return err
	}
	if len(user.Password) < 6 {
		log.Error("Password too short")
		resp := c.JSON(http.StatusConflict, helper.ErrorLog(http.StatusConflict, "Password too short", "EXT_REF"))
		return resp
	}
	DB := db.DB()
	var count int
	sqlStatement := `Select count(username) from users where username=?`
	err = DB.QueryRow(sqlStatement, user.Username).Scan(&count)
	if err != nil {
		log.Error(err.Error())
	}
	if count > 0 {
		log.Error("username already used")
		resp := c.JSON(http.StatusConflict, helper.ErrorLog(http.StatusConflict, "username already used", "EXT_REF"))
		return resp
	}
	//hashing password (even it's a CTF, stick to the good habits)
	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 5)
	if err != nil {
		resp := c.JSON(http.StatusInternalServerError, helper.ErrorLog(http.StatusInternalServerError, " Error While Hashing Password", "EXT_REF"))
		return resp
	}
	user.Password = string(hash)
	user.DateCreated = helper.DateTime()
	user.Token = helper.JwtGenerator(user.Username, user.Firstname, user.Lastname, os.Getenv("SECRET"))
	stmt, err := DB.Prepare("Insert into users (username,firstname,lastname,password,token,datecreated) VALUES (?,?,?,?,?,?)")
	if err != nil {
		resp := c.JSON(http.StatusInternalServerError, helper.ErrorLog(http.StatusInternalServerError, "Error when prepare statement : "+err.Error(), "EXT_REF"))
		return resp
	}
	_, err = stmt.Exec(user.Username, user.Firstname, user.Lastname, user.Password, user.Token, user.DateCreated)
	if err != nil {
		log.Error(err)
		resp := c.JSON(http.StatusInternalServerError, helper.ErrorLog(http.StatusInternalServerError, "Error when execute statement : "+err.Error(), "EXT_REF"))
		return resp
	}
	resp := c.JSON(http.StatusOK, user)
	log.Info()
	return resp
}

type Flag struct {
	Flag string `json:"flag"`
}

func LoginController(c echo.Context) error {
	var user models.Users
	payload, _ := io.ReadAll(c.Request().Body)
	err := json.Unmarshal(payload, &user)

	if err != nil {
		log.Error(err)
		return err
	}
	var result models.Users
	DB := db.DB()
	sqlStatement := "select * from users where username=?"

	err = DB.QueryRow(sqlStatement, user.Username).Scan(&result.Username, &result.Firstname, &result.Lastname, &result.Password, &result.Token, &result.DateCreated)
	if err != nil {
		log.Error(err)
		resp := c.JSON(http.StatusInternalServerError, helper.ErrorLog(http.StatusInternalServerError, "Invalid Username", "EXT_REF"))
		return resp
	}

	err = bcrypt.CompareHashAndPassword([]byte(result.Password), []byte(user.Password))
	if err != nil {
		log.Error("Invalid Password :", err)
		resp := c.JSON(http.StatusInternalServerError, helper.ErrorLog(http.StatusInternalServerError, "Invalid Password", "EXT_REF"))
		return resp
	}
	password := []rune(user.Password)
	result.Token = helper.JwtGenerator(result.Username, result.Firstname, result.Lastname, os.Getenv("SECRET"))
	if len(password) < 6 {
		flag := os.Getenv("FLAG")
		res := &Flag{
			Flag: flag,
		}
		resp := c.JSON(http.StatusOK, res)
		log.Info()
		return resp
	}
	resp := c.JSON(http.StatusOK, result)
	log.Info()
	return resp
}
