package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	filePath = "/home/mininet/project/data/server_data/files/"
)

type server struct {
	servers map[string]*http.Server
	wg      *sync.WaitGroup
}

func NewServer(firstPort int) *server {
	r := gin.Default()

	r.GET("/file/:name", serveFile)

	srv := server{
		servers: map[string]*http.Server{
			KindFile: {
				Addr:    fmt.Sprintf(":%v", firstPort+PortOffsets[KindFile]),
				Handler: r,
			},
		},
		wg: &sync.WaitGroup{},
	}

	return &srv
}

func (r *server) Start() {
	for _, s := range r.servers {
		s := s
		go func() {
			r.wg.Add(1)

			if err := s.ListenAndServe(); err != nil {
				if err != http.ErrServerClosed {
					log.Fatal(err)
				}
			}
		}()
	}
}

func (r *server) Stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for _, s := range r.servers {
		s := s
		go func() {
			defer r.wg.Done()

			if err := s.Shutdown(ctx); err != nil {
				log.Println("Server forced to shutdown:", err)
			}
		}()
	}

	r.wg.Wait()
}

func validateFileName(name string) error {
	if strings.ContainsRune(name, '/') {
		return errors.New("incorrect file path")
	}
	return nil
}

func serveFile(ctx *gin.Context) {
	name := ctx.Param("name")
	if err := validateFileName(name); err != nil {
		ginError(ctx, http.StatusBadRequest, err)
		return
	}

	ctx.File(filePath + name)
}
