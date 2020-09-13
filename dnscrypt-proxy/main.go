package main

import (
	"compress/gzip"
	crypto_rand "crypto/rand"
	"encoding/binary"
	"encoding/gob"
	"flag"
	"fmt"
	"github.com/jedisct1/dlog"
	"github.com/kardianos/service"
	"math/rand"
	"os"
	"runtime"
	"strconv"
	"sync"
	"time"
)

const (
	AppVersion            = "2.0.45"
	DefaultConfigFileName = "dnscrypt-proxy.toml"
)

type App struct {
	wg    sync.WaitGroup
	quit  chan struct{}
	proxy *Proxy
	flags *ConfigFlags
}

func main() {
	TimezoneSetup()
	dlog.Init("dnscrypt-proxy-home", dlog.SeverityNotice, "DAEMON")

	seed := make([]byte, 8)
	crypto_rand.Read(seed)
	rand.Seed(int64(binary.LittleEndian.Uint64(seed[:])))

	pwd, err := os.Getwd()
	if err != nil {
		dlog.Fatal("Unable to find the path to the current directory")
	}

	svcFlag := flag.String("service", "", fmt.Sprintf("Control the system service: %q", service.ControlAction))
	version := flag.Bool("version", false, "print current proxy version")
	resolve := flag.String("resolve", "", "resolve a name using system libraries")
	flags := ConfigFlags{}
	flags.List = flag.Bool("list", false, "print the list of available resolvers for the enabled filters")
	flags.ListAll = flag.Bool("list-all", false, "print the complete list of available resolvers, ignoring filters")
	flags.JSONOutput = flag.Bool("json", false, "output list as JSON")
	flags.Check = flag.Bool("check", false, "check the configuration file and exit")
	flags.ConfigFile = flag.String("config", DefaultConfigFileName, "Path to the configuration file")
	flags.Child = flag.Bool("child", false, "Invokes program as a child process")
	flags.NetprobeTimeoutOverride = flag.Int("netprobe-timeout", 60, "Override the netprobe timeout")
	flags.ShowCerts = flag.Bool("show-certs", false, "print DoH certificate chain hashes")

	flag.Parse()

	if *version {
		fmt.Println(AppVersion)
		os.Exit(0)
	}
	if resolve != nil && len(*resolve) > 0 {
		Resolve(*resolve)
		os.Exit(0)
	}

	app := &App{
		flags: &flags,
	}

	svcConfig := &service.Config{
		Name:             "dnscrypt-proxy-home",
		DisplayName:      "DNSCrypt client proxy",
		Description:      "Encrypted/authenticated DNS proxy by @dnscrypt. With some additional featuref by @antonme",
		WorkingDirectory: pwd,
		Arguments:        []string{"-config", *flags.ConfigFile},
	}
	svc, err := service.New(app, svcConfig)
	if err != nil {
		svc = nil
		dlog.Debug(err)
	}

	app.proxy = NewProxy()
	_ = ServiceManagerStartNotify()
	if len(*svcFlag) != 0 {
		if svc == nil {
			dlog.Fatal("Built-in service installation is not supported on this platform")
		}
		if err := service.Control(svc, *svcFlag); err != nil {
			dlog.Fatal(err)
		}
		if *svcFlag == "install" {
			dlog.Notice("Installed as a service. Use `-service start` to start")
		} else if *svcFlag == "uninstall" {
			dlog.Notice("Service uninstalled")
		} else if *svcFlag == "start" {
			dlog.Notice("Service started")
		} else if *svcFlag == "stop" {
			dlog.Notice("Service stopped")
		} else if *svcFlag == "restart" {
			dlog.Notice("Service restarted")
		}
		return
	}
	if svc != nil {
		if err := svc.Run(); err != nil {
			dlog.Fatal(err)
		}
	} else {
		app.Start(nil)
	}
}

func (app *App) Start(service service.Service) error {
	if service != nil {
		go func() {
			app.AppMain()
		}()
	} else {
		app.AppMain()
	}
	return nil
}

func (app *App) AppMain() {
	if err := ConfigLoad(app.proxy, app.flags); err != nil {
		dlog.Fatal(err)
	}
	if err := PidFileCreate(); err != nil {
		dlog.Criticalf("Unable to create the PID file: %v", err)
	}
	if err := app.proxy.InitPluginsGlobals(); err != nil {
		dlog.Fatal(err)
	}
	app.quit = make(chan struct{})
	app.wg.Add(1)
	app.proxy.StartProxy()
	runtime.GC()
	<-app.quit
	dlog.Notice("Quit signal received...")
	app.wg.Done()
}

func (app *App) SaveCache() error {
	cachedResponses.RLock()
	defer cachedResponses.RUnlock()

	if cachedResponses.cache != nil && cachedResponses.cache.Len()>0 {
		dlog.Notice("Saving "+ strconv.Itoa(cachedResponses.cache.Len()) + "cached responses")

		saveFile, _ := os.Create("/Users/anton/dev/dnscrypt-proxy.cache")
		defer saveFile.Close()

		saveZip := gzip.NewWriter(saveFile)
		defer saveZip.Close()

		enc := gob.NewEncoder(saveZip)

		cachedResponses.RLock()
		defer cachedResponses.RUnlock()

		err := enc.Encode(cachedResponses.cache.Len())
		if err != nil {
			return err
		}

		for keyNum := range cachedResponses.cache.Keys() {

			cacheKey := cachedResponses.cache.Keys()[keyNum]
			err = enc.Encode(cacheKey)
			if err != nil {
				return err
			}

			cachedAny, _ := cachedResponses.cache.Peek(cacheKey)
			cached := cachedAny.(CachedResponse)
			msg := cached.msg

			err = enc.Encode(cached.expiration)
			if err != nil {
				return err
			}
			dlog.Notice(cached.msg.Question)
			dlog.Notice(cached.expiration)
			fmt.Println("Expiration: ",cached.expiration.Sub(time.Now()))
			packet, _ := msg.PackBuffer(nil)
			err = enc.Encode(packet)
			if err != nil {
				return err
			}

			qHash := computeCacheKey(nil, &msg)
			_, queueExist := app.proxy.queueLock.queue[qHash]
			err = enc.Encode(queueExist)
			if err != nil {
				return err
			}
		}
	} else {
		dlog.Notice("No cache to save")
	}
	return nil
}

func (app *App) Stop(service service.Service) error {
	PidFileRemove()

	err := app.SaveCache()
	if err != nil {
		dlog.Fatal("Can't save cached responses to a file")
	}

	dlog.Notice("Stopped.")
	return nil
}
