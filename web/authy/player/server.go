package main

import (
	"net/http"
	"time"

	controllers "github.com/blackhat/controller"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func main() {
	e := echo.New()

	// e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{echo.GET, echo.POST},
	}))

	e.POST("/login", controllers.LoginController)
	e.POST("/registration", controllers.Registration)
	s := &http.Server{
		Addr:         ":1323",
		ReadTimeout:  20 * time.Minute,
		WriteTimeout: 20 * time.Minute,
	}
	e.Logger.Fatal(e.StartServer(s))
}
