package main

import (
	"compress/gzip"
	"crypto/sha512"
	"encoding/binary"
	"encoding/gob"
	lru "github.com/hashicorp/golang-lru"
	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
	"os"
	"sync"
	"time"
)

type CachedResponse struct {
	Expiration time.Time
	Msg        dns.Msg
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

func (cachedResponses *CachedResponses) LoadCache(cacheFilename string, cacheSize int) error {
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
				Expiration: expiration,
				Msg:        msg,
			}

			if time.Now().Before(cachedResponse.Expiration) {
				updateTTL(&msg, cachedResponse.Expiration)
			}

			cachedResponses.cache.Add(key, cachedResponse)

			if frequent {
				dlog.Debugf("Question is [%s], frequent, Expiration date: %s (TTL: %d)", msg.Question[0].Name, expiration, expiration.Sub(time.Now())/time.Second)
				cachedResponses.cache.Add(key, cachedResponse)
			} else {
				dlog.Debugf("Question is [%s], non frequent, Expiration date: %s (TTL: %d)", msg.Question[0].Name, expiration, expiration.Sub(time.Now())/time.Second)
			}
			for i := range msg.Answer {
				dlog.Debugf("Answer: [%s]", msg.Answer[i])
			}

		}
	}

	return nil
}

/*
type SavedResponse struct {
	Expiration time.Time
	Frequent   bool
	Msg        dns.Msg
}
func (cachedResponses *CachedResponses) LoadFromFileNew(cacheFilename string, cacheSize int) error {
	loadFile, _ := os.Open(cacheFilename)
	defer loadFile.Close()

	loadZip, err := gzip.NewReader(loadFile)
	if err != nil {
		return err
	}

	dec := gob.NewDecoder(loadZip)

	dlog.Noticef("Loading (new way) cached responses from [%s]", cacheFilename)

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
	i:=1
	for {
		var key [32]byte
		var savedResponse SavedResponse

		dlog.Debugf("== Loading %d response =====================", i)
		i++
		err = dec.Decode(&savedResponse)
		if err != nil {
			dlog.Warn(err)
			return err
		}

		cachedResponse := CachedResponse{
			Expiration: savedResponse.Expiration,
			Msg:        savedResponse.Msg,
		}

		if time.Now().Before(cachedResponse.Expiration) {
			updateTTL(&cachedResponse.Msg, cachedResponse.Expiration)
		}

		cachedResponses.cache.Add(key, cachedResponse)

		if savedResponse.Frequent {
			dlog.Debugf("Question is [%s], frequent, Expiration date: %s (TTL: %d)", savedResponse.Msg.Question[0].Name, savedResponse.Expiration, cachedResponse.Expiration.Sub(time.Now())/time.Second)
			cachedResponses.cache.Add(key, cachedResponse)
		} else {
			dlog.Debugf("Question is [%s], not frequent, Expiration date: %s (TTL: %d)", savedResponse.Msg.Question[0].Name, savedResponse.Expiration, cachedResponse.Expiration.Sub(time.Now())/time.Second)
		}

	}
	dlog.Noticef("Loaded (new way) %d cached responses", i)


	return nil
}
func (cachedResponses *CachedResponses) SaveCacheNew(cacheFilename string) error {
	cachedResponses.RLock()
	defer cachedResponses.RUnlock()

	if cachedResponses.cache != nil && cachedResponses.cache.Len() > 0 {

		dlog.Noticef("Saving (new way) %d cached responses", cachedResponses.cache.Len())

		saveFile, _ := os.Create(cacheFilename)
		defer saveFile.Close()

		saveZip := gzip.NewWriter(saveFile)
		defer saveZip.Close()

		enc := gob.NewEncoder(saveZip)

		cachedResponses.RLock()
		defer cachedResponses.RUnlock()

		keys := cachedResponses.cache.Keys()
		for keyNum := range keys {

			cacheKey := keys[keyNum]
			cachedAny, _ := cachedResponses.cache.Peek(cacheKey)
			cached := cachedAny.(CachedResponse)

			_, mapValueExist := cachedResponses.fetchLock[cacheKey.([32]byte)]

			savedResponse := SavedResponse{
				Expiration: cached.Expiration,
				Frequent:   mapValueExist,
				Msg:        cached.Msg,
			}
			dlog.Debugf("Saving response for [%s], expiration: [%s]", cached.Msg.Question[0].Name, cached.Expiration)

			err := enc.Encode(savedResponse)

			if err != nil {
				return err
			}
		}
	} else {
		dlog.Notice("No cache to save")
	}
	return nil
}
*/

func (cachedResponses *CachedResponses) SaveCache(cacheFilename string) error {
	cachedResponses.RLock()
	defer cachedResponses.RUnlock()

	if cachedResponses.cache != nil && cachedResponses.cache.Len() > 0 {

		dlog.Noticef("Saving %d cached responses", cachedResponses.cache.Len())

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

		keys := cachedResponses.cache.Keys()

		for keyNum := range keys {

			cacheKey := keys[keyNum]
			err = enc.Encode(cacheKey)
			if err != nil {
				return err
			}

			cachedAny, _ := cachedResponses.cache.Peek(cacheKey)
			cached := cachedAny.(CachedResponse)
			msg := cached.Msg

			err = enc.Encode(cached.Expiration)
			if err != nil {
				return err
			}
			dlog.Debug(cached.Msg.Question)
			dlog.Debug(cached.Expiration)
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

	synth := cached.Msg
	synth.Id = msg.Id
	synth.Response = true
	synth.Compress = true
	synth.Question = msg.Question

	if time.Now().After(cached.Expiration) {
		if pluginsState.cacheForced == false || pluginsState.forceRequest {
			pluginsState.sessionData["stale"] = &synth
			return nil
		}
		pluginsState.forceRequest = true
	} else {
		updateTTL(&cached.Msg, cached.Expiration)
	}

	pluginsState.synthResponse = &synth
	pluginsState.action = PluginsReturnCodeSynth
	pluginsState.cacheHit = true
	pluginsState.cachedTTL = cached.Expiration.Sub(time.Now())

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
		err := cachedResponses.LoadCache(proxy.cacheFilename, proxy.cacheSize)
		if err != nil {
			dlog.Warnf("Error while loading cache from [%s]: %s", proxy.cacheFilename, err)
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
		Expiration: time.Now().Add(ttl),
		Msg:        *msg,
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

	updateTTL(msg, cachedResponse.Expiration)

	return nil
}
