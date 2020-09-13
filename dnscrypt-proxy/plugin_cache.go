package main

import (
	"compress/gzip"
	"crypto/sha512"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"github.com/jedisct1/dlog"
	"os"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru"
	"github.com/miekg/dns"
)

type CachedResponse struct {
	expiration time.Time
	msg        dns.Msg
}

type CachedResponses struct {
	sync.RWMutex
	cache *lru.ARCCache
}

var cachedResponses CachedResponses

func computeCacheKey(pluginsState *PluginsState, msg *dns.Msg) [32]byte {
	question := msg.Question[0]
	h := sha512.New512_256()
	var tmp [5]byte
	binary.LittleEndian.PutUint16(tmp[0:2], question.Qtype)
	binary.LittleEndian.PutUint16(tmp[2:4], question.Qclass)
	if pluginsState != nil && pluginsState.dnssec {
		tmp[4] = 1
	}
	h.Write(tmp[:])
	normalizedRawQName := []byte(question.Name)
	NormalizeRawQName(&normalizedRawQName)
	h.Write(normalizedRawQName)
	var sum [32]byte
	h.Sum(sum[:0])

	return sum
}

// ---

type PluginCache struct {
}

func (plugin *PluginCache) Name() string {
	return "cache"
}

func (plugin *PluginCache) Description() string {
	return "DNS cache (reader)."
}

func (plugin *PluginCache) Init(proxy *Proxy) error {
	dlog.Notice("Is this the place")
	plugin.LoadFromFile()
	return nil
}

func (plugin *PluginCache) LoadFromFile() error {
	dlog.Notice("Loading cached responses from [/Users/anton/dev/dnscrypt-proxy.cache]")

	loadFile, _ := os.Open("/Users/anton/dev/dnscrypt-proxy.cache")
	defer loadFile.Close()

	loadZip, _ := gzip.NewReader(loadFile)

	dec := gob.NewDecoder(loadZip)
	var keysnum int

	dec.Decode(&keysnum)
	dlog.Notice(keysnum)

	if keysnum > 0 {
		for i := 0; i < keysnum; i++ {
			var key [32]byte
			var msg dns.Msg
			var expiration time.Time
			var packet []byte
			var repeated bool

			dec.Decode(&key)
			dec.Decode(&expiration)
			dec.Decode(&packet)
			fmt.Println("Expiration date: ", expiration)
			msg.Unpack(packet)
			dec.Decode(&repeated)

			fmt.Println("Question: ", msg.Question)
			fmt.Println("Answer: ", msg.Answer)
			fmt.Println("Repeated: ", repeated)
		}
	}

	return nil
}

func (plugin *PluginCache) Drop() error {
	return nil
}

func (plugin *PluginCache) Reload() error {
	return nil
}

func (plugin *PluginCache) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	cacheKey := computeCacheKey(pluginsState, msg)
	cachedResponses.RLock()
	defer cachedResponses.RUnlock()
	if cachedResponses.cache == nil {
		return nil
	}
	cachedAny, ok := cachedResponses.cache.Get(cacheKey)
	if !ok {
		return nil
	}
	cached := cachedAny.(CachedResponse)

	synth := cached.msg
	synth.Id = msg.Id
	synth.Response = true
	synth.Compress = true
	synth.Question = msg.Question

	if time.Now().After(cached.expiration.Add(-1*time.Second)) && pluginsState.cacheExpired {
		pluginsState.sessionData["stale"] = &synth
		return nil
	}

	if time.Now().After(cached.expiration.Add(-1 * time.Second)) {
		pluginsState.cacheExpired = true
	}

	if time.Now().Before(cached.expiration) {
		updateTTL(&cached.msg, cached.expiration)
	}

	pluginsState.synthResponse = &synth
	pluginsState.action = PluginsReturnCodeSynth
	pluginsState.cacheHit = true
	pluginsState.cachedTTL = cached.expiration.Sub(time.Now())

	return nil
}

// ---

type PluginCacheResponse struct {
}

func (plugin *PluginCacheResponse) Name() string {
	return "cache_response"
}

func (plugin *PluginCacheResponse) Description() string {
	return "DNS cache (writer)."
}

func (plugin *PluginCacheResponse) Init(proxy *Proxy) error {
	return nil
}

func (plugin *PluginCacheResponse) Drop() error {
	return nil
}

func (plugin *PluginCacheResponse) Reload() error {
	return nil
}

func (plugin *PluginCacheResponse) Eval(pluginsState *PluginsState, msg *dns.Msg) error {
	if msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError && msg.Rcode != dns.RcodeNotAuth {
		return nil
	}
	if msg.Truncated {
		return nil
	}
	cacheKey := computeCacheKey(pluginsState, msg)
	ttl := getMinTTL(msg, pluginsState.cacheMinTTL, pluginsState.cacheMaxTTL, pluginsState.cacheNegMinTTL, pluginsState.cacheNegMaxTTL)

	pluginsState.cachedTTL = ttl
	cachedResponse := CachedResponse{
		expiration: time.Now().Add(ttl),
		msg:        *msg,
	}

	cachedResponses.Lock()
	if cachedResponses.cache == nil {
		var err error
		cachedResponses.cache, err = lru.NewARC(pluginsState.cacheSize)
		if err != nil {
			cachedResponses.Unlock()
			return err
		}
	}
	cachedResponses.cache.Add(cacheKey, cachedResponse)
	cachedResponses.Unlock()
	/*if pluginsState.action == PluginsActionPrefetch {
		pluginsState.returnCode = PluginsReturnCodePostfetch
	}*/
	updateTTL(msg, cachedResponse.expiration)

	return nil
}
