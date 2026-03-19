package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

func main() {
	log.Printf("Starting Provenance Graph SBOM Linker Simple Server")

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})

	addr := ":8081"
	log.Printf("Listening on %s", addr)
	if err := router.Run(addr); err != nil {
		log.Fatalf("Server error: %v", err)
	}
	fmt.Println("Server stopped")
}
