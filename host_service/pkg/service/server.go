package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const (
	filePath = "/home/mininet/project/data/server_data/files/"
)

var fileDescriptors = make(map[string]*os.File)

type server struct {
	servers map[string]*http.Server
	wg      *sync.WaitGroup
}

func NewServer(firstPort int) *server {
	fileServer := gin.Default()
	webServer := gin.Default()
	videoServer := gin.Default()

	fileServer.GET("/file/:name", serveContent)
	webServer.GET("/web/:name", serveContent)
	videoServer.GET("/video/:name", serveContent)

	srv := server{
		servers: map[string]*http.Server{
			KindFile: {
				Addr:    fmt.Sprintf(":%v", firstPort+PortOffsets[KindFile]),
				Handler: fileServer,
			},
			KindWeb: {
				Addr:    fmt.Sprintf(":%v", firstPort+PortOffsets[KindWeb]),
				Handler: webServer,
			},
			KindVideo: {
				Addr:    fmt.Sprintf(":%v", firstPort+PortOffsets[KindVideo]),
				Handler: videoServer,
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

func serveContent(ctx *gin.Context) {
	var (
		req VideoRequest
		f   *os.File
		err error
	)

	if err = ctx.BindJSON(&req); err != nil {
		ginError(ctx, http.StatusBadRequest, err)
		return
	}

	log.Println(req)

	if err := validateFileName(req.Name); err != nil {
		ginError(ctx, http.StatusBadRequest, err)
		return
	}

	if req.ID != "" {
		f = fileDescriptors[req.ID]
	}

	if f == nil {
		f, err = os.Open(filePath + req.Name)
		if err != nil {
			ginError(ctx, http.StatusBadRequest, err)
			return
		}

		req.ID = uuid.NewString()
		fileDescriptors[req.ID] = f
	}

	ctx.Header(headerID, req.ID)

	if _, err = f.Seek(req.Offset, 0); err != nil {
		ginError(ctx, http.StatusBadRequest, err)
		return
	}

	log.Println("assumed the position")

	b := make([]byte, req.Length)

	n, err := f.Read(b)
	if err != nil && err != io.EOF {
		ginError(ctx, http.StatusBadRequest, err)
		return
	}

	log.Println("read portion")

	if n < int(req.Length) || err == io.EOF {
		log.Println("got to the end of file")

		if err = fileDescriptors[req.ID].Close(); err != nil {
			ginError(ctx, http.StatusInternalServerError, err)
			return
		}

		delete(fileDescriptors, req.ID)
	}

	log.Println(n)

	ctx.Data(http.StatusOK, "application/octet-stream", b[:n])

	log.Println("wrote response")
}
