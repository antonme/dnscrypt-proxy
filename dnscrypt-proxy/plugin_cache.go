package main

import (
	"compress/gzip"
	"crypto/sha512"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"github.com/jedisct1/dlog"
	"os"
	"strconv"
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
	cache     *lru.ARCCache
	fetchLock map[[32]byte]bool
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

func (cachedResponses *CachedResponses) LoadFromFile(cacheFilename string, cacheSize int) error {
	loadFile, _ := os.Open(cacheFilename)
	defer loadFile.Close()

	loadZip, err := gzip.NewReader(loadFile)
	if err != nil {
		return err
	}

	dec := gob.NewDecoder(loadZip)
	var keysnum int

	err = dec.Decode(&keysnum)
	if err != nil {
		return err
	}

	if keysnum > 0 {
		dlog.Noticef("Loading %d cached responses from [%s]", keysnum, cacheFilename)

		cachedResponses.Lock()
		defer cachedResponses.Unlock()

		if cachedResponses.cache == nil {

			cachedResponses.cache, err = lru.NewARC(cacheSize)
			cachedResponses.fetchLock = make(map[[32]byte]bool)

			if err != nil {
				cachedResponses.Unlock()
				return err
			}
		}

		for i := 0; i < keysnum; i++ {
			var key [32]byte
			var msg dns.Msg
			var expiration time.Time
			var packet []byte
			var frequent bool

			dlog.Debugf("== Loading %d response of %d =====================", i+1, keysnum)

			err = dec.Decode(&key)
			if err != nil {
				return err
			}

			err = dec.Decode(&expiration)
			if err != nil {
				return err
			}

			err = dec.Decode(&packet)
			if err != nil {
				return err
			}

			err = dec.Decode(&frequent)
			if err != nil {
				return err
			}

			err = msg.Unpack(packet)
			if err != nil {
				return err
			}

			cachedResponse := CachedResponse{
				expiration: expiration,
				msg:        msg,
			}

			if time.Now().Before(cachedResponse.expiration) {
				updateTTL(&msg, cachedResponse.expiration)
			}

			cachedResponses.cache.Add(key, cachedResponse)

			if frequent {
				dlog.Debugf("Question is [%s], frequent, expiration date: %s (TTL: %d)", msg.Question[0].Name, expiration, expiration.Sub(time.Now())/time.Second)
				cachedResponses.cache.Add(key, cachedResponse)
			} else {
				dlog.Debugf("Question is [%s], non frequent, expiration date: %s (TTL: %d)", msg.Question[0].Name, expiration, expiration.Sub(time.Now())/time.Second)
			}
			for i := range msg.Answer {
				dlog.Debugf("Answer: [%s]", msg.Answer[i])
			}

		}
	}

	return nil
}

func (cachedResponses *CachedResponses) SaveCache(cacheFilename string) error {
	cachedResponses.RLock()
	defer cachedResponses.RUnlock()

	if cachedResponses.cache != nil && cachedResponses.cache.Len() > 0 {
		dlog.Notice("Saving " + strconv.Itoa(cachedResponses.cache.Len()) + "cached responses")

		saveFile, _ := os.Create(cacheFilename)
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
			fmt.Println("Expiration: ", cached.expiration.Sub(time.Now()))
			packet, _ := msg.PackBuffer(nil)
			err = enc.Encode(packet)
			if err != nil {
				return err
			}

			qHash := computeCacheKey(nil, &msg)
			_, queueExist := cachedResponses.fetchLock[qHash]
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

// ---

type PluginCache struct {
}

func (plugin *PluginCache) Name() string {
	return "cache"
}

func (plugin *PluginCache) Description() string {
	return "DNS cache (reader)."
}

func (plugin *PluginCache) Init(_ *Proxy) error {
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

	if time.Now().After(cached.expiration) {
		if pluginsState.cacheForced == false || pluginsState.forceRequest {
			pluginsState.sessionData["stale"] = &synth
			return nil
		}
		pluginsState.forceRequest = true
	} else {
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
	if proxy != nil && proxy.cachePersistent {
		err := cachedResponses.LoadFromFile(proxy.cacheFilename, proxy.cacheSize)
		if err != nil {
			dlog.Warnf("Error while loading cache from [%s]", proxy.cacheFilename)
		}
	}
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
		cachedResponses.fetchLock = make(map[[32]byte]bool)

		if err != nil {
			cachedResponses.Unlock()
			return err
		}
	}
	cachedResponses.cache.Add(cacheKey, cachedResponse)
	cachedResponses.Unlock()

	updateTTL(msg, cachedResponse.expiration)

	return nil
}
