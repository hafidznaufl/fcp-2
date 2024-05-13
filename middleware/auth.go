package middleware

import (
	"a21hc3NpZ25tZW50/model"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

func Auth() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		// session token ambil dari cookie dengan key "session_token"
		cookie, err := c.Cookie("session_token")

		// case jika tidak ada "session_token"
		if err != nil {
			if c.GetHeader("Content-Type") == "application/json" {
				// case jika "Content-Type" sesuai, status code = 401
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			} else {
				// case jika "Content-Type" tidak sesuai, status code = 303
				c.Redirect(http.StatusSeeOther, "/login")
			}

			c.Abort()
			return
		}

		// case jika ada "session_token" lalu ambil model Claims
		tokenClaims := &model.Claims{}

		// parse jwt
		token, err := jwt.ParseWithClaims(cookie, tokenClaims, func(t *jwt.Token) (interface{}, error) {
			return model.JwtKey, nil
		})
		if err != nil || !token.Valid {
			// case jika parse gagal, status code = 400
			c.JSON(http.StatusBadRequest, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		// jika parse berhasil, set token dan call next middleware
		c.Set("email", tokenClaims.Email)
		c.Next()
	})
}