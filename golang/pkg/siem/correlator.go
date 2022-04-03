package siem

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"golang/pkg/ginext"

	"github.com/gin-gonic/gin"
)

type Config struct {
	ListenOn      string
	PortActionURL string
	PortALConfig  *ALConfig
	FlowALConfig  *ALConfig
}

type Correlator struct {
	cfg          *Config
	receiver     *gin.Engine
	portALWorker Worker
}

func NewCorrelator(cfg *Config) *Correlator {
	gin.SetMode(gin.ReleaseMode)
	receiver := gin.Default()

	corr := Correlator{
		cfg:      cfg,
		receiver: receiver,
	}

	corr.portALWorker = *NewWorker(GetPortStateKey, corr.onPortALFull, *NewActiveList(cfg.PortALConfig))

	receiver.POST("/port", func(ctx *gin.Context) {
		var ps PortState
		if err := ctx.BindJSON(&ps); err != nil {
			ginext.GinError(ctx, http.StatusBadRequest, err)
			return
		}

		corr.portALWorker.Push(Event{
			Time:      time.Now(),
			PortState: &ps,
		})

		ctx.Status(http.StatusOK)
	})

	return &corr
}

func (r *Correlator) Start() {
	go r.portALWorker.Work()
	r.receiver.Run(r.cfg.ListenOn)
}

func (r *Correlator) onPortALFull(key string) {
	go func(key string) {
		resp, err := http.Post(r.cfg.PortActionURL, "application/json", strings.NewReader(fmt.Sprintf(`{"mac": "%v"}`, key)))
		if err != nil {
			log.Println(err)
			return
		}

		defer ginext.DiscardBody(resp)

		if resp.StatusCode != http.StatusOK {
			b, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				log.Println(err)
				return
			}
			log.Printf("%s\n", b)
		}
	}(key)
}
