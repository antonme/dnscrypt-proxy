package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
)

type PluginQueryLog struct {
	logger        io.Writer
	format        string
	ignoredQtypes []string
}

func (plugin *PluginQueryLog) Name() string {
	return "query_log"
}

func (plugin *PluginQueryLog) Description() string {
	return "Log DNS queries."
}

func (plugin *PluginQueryLog) Init(proxy *Proxy) error {
	plugin.logger = Logger(proxy.logMaxSize, proxy.logMaxAge, proxy.logMaxBackups, proxy.queryLogFile)
	plugin.format = proxy.queryLogFormat
	plugin.ignoredQtypes = proxy.queryLogIgnoredQtypes

	return nil
}

func (plugin *PluginQueryLog) Drop() error {
	return nil
}

func (plugin *PluginQueryLog) Reload() error {
	return nil
}

func (plugin *PluginQueryLog) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	question := msg.Question[0]
	qType, ok := dns.TypeToString[question.Qtype]

	if !ok {
		switch question.Qtype { //Until miekg/dns get updated to support SVCB
		case 65:
			qType = "HTTPS"
		case 64:
			qType = "SVCB"
		case 63:
			qType = "ZONEMD"
		default:
			qType = strconv.FormatUint(uint64(question.Qtype), 10)
		}
	}

	if len(plugin.ignoredQtypes) > 0 {
		for _, ignoredQtype := range plugin.ignoredQtypes {
			if strings.EqualFold(ignoredQtype, qType) {
				return nil
			}
		}
	}
	clientIPStr := "-"
	if pluginsState.clientProto == "udp" {
		clientIPStr = (*pluginsState.clientAddr).(*net.UDPAddr).IP.String()
	} else {
		clientIPStr = (*pluginsState.clientAddr).(*net.TCPAddr).IP.String()
	}
	qName := pluginsState.qName

	if pluginsState.cacheHit && !pluginsState.forceRequest {
		pluginsState.serverName = "-"
		pluginsState.returnCode = PluginsReturnCodeCacheHit
	} else if pluginsState.cacheHit {
		pluginsState.serverName = "-"
		pluginsState.returnCode = PluginsReturnCodeForcedCache
	} else {
		switch pluginsState.returnCode {
		case PluginsReturnCodeSynth, PluginsReturnCodeCloak, PluginsReturnCodeParseError:
			pluginsState.serverName = "-"
		case PluginsReturnCodePostfetch:
			clientIPStr = "-"
		}

	}

	returnCode, ok := PluginsReturnCodeToString[pluginsState.returnCode]
	if !ok {
		returnCode = string(returnCode)
	}

	var requestDuration time.Duration
	if !pluginsState.requestStart.IsZero() && !pluginsState.requestEnd.IsZero() {
		requestDuration = pluginsState.requestEnd.Sub(pluginsState.requestStart)
	}
	if pluginsState.action == PluginsActionDrop && pluginsState.forceRequest {
		//		return nil
		clientIPStr = "-"
	}
	var line string
	if plugin.format == "tsv" {
		now := time.Now()
		year, month, day := now.Date()
		hour, minute, second := now.Clock()
		millis := time.Now().Nanosecond() / 1000
		ttl := pluginsState.cachedTTL / time.Second
		tsStr := fmt.Sprintf("[%d-%02d-%02d %02d:%02d:%02d.%06d]", year, int(month), day, hour, minute, second, millis)
		line = fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%dms\t%d\t%s\n", tsStr, clientIPStr, StringQuote(qName), qType, returnCode, requestDuration/time.Millisecond,
			ttl, StringQuote(pluginsState.serverName))
	} else if plugin.format == "ltsv" {
		cached := 0
		if pluginsState.cacheHit {
			cached = 1
		}
		line = fmt.Sprintf("time:%d\thost:%s\tmessage:%s\ttype:%s\treturn:%s\tcached:%d\tduration:%d\tserver:%s\n",
			time.Now().Unix(), clientIPStr, StringQuote(qName), qType, returnCode, cached, requestDuration/time.Millisecond, StringQuote(pluginsState.serverName))
	} else {
		dlog.Fatalf("Unexpected log format: [%s]", plugin.format)
	}
	if plugin.logger == nil {
		return errors.New("Log file not initialized")
	}
	_, _ = plugin.logger.Write([]byte(line))

	return nil
}
