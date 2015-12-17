package main

import (
	"github.com/jtblin/docker-auth/app"

	"runtime"

	log "github.com/Sirupsen/logrus"
	"github.com/spf13/pflag"
)

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	s := app.NewDockerAuthServer()
	s.AddFlags(pflag.CommandLine)
	pflag.Parse()

	if err := s.Run(); err != nil {
		log.Fatalf("%v\n", err)
	}
}
