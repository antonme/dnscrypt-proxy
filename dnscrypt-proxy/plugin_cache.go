package main

import (
	"bufio"
	"crypto/sha512"
	"encoding/binary"
	"encoding/gob"
	"encoding/json"
	"fmt"
	lru "github.com/hashicorp/golang-lru"
	"github.com/jedisct1/dlog"
	"github.com/miekg/dns"
	"io"
	"os"
	"sync"
	"time"
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
	dnssec := false

	if pluginsState == nil {
		edns0 := msg.IsEdns0()
		if edns0 != nil {
			dnssec = edns0.Do()
		}
	} else {
		dnssec = pluginsState.dnssec
	}

	question := msg.Question[0]
	h := sha512.New512_256()
	var tmp [5]byte
	binary.LittleEndian.PutUint16(tmp[0:2], question.Qtype)
	binary.LittleEndian.PutUint16(tmp[2:4], question.Qclass)
	if dnssec {
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

type SavedResponse struct {
	Expiration time.Time
	Frequent   bool
	Packet     []byte
}

type CacheFileHeader struct {
	Description      string    `json:"description"`
	AppName          string    `json:"app_name"`
	AppVersion       string    `json:"app_version"`
	ProtoVersion     uint32    `json:"proto_version"`
	TimeSaved        time.Time `json:"time_saved"`
	ItemsCount       int       `json:"items_count"`
	OriginalLocation string    `json:"original_location"`
	Compressed       bool      `json:"compressed"`
	Links            []string  `json:"links"`
}

func (cachedResponses *CachedResponses) LoadCache(cacheFilename string, cacheSize int) error {
	startTime := time.Now()
	loadFile, err := os.Open(cacheFilename)
	if err != nil {
		return err
	}

	defer loadFile.Close()

	var header CacheFileHeader

	reader := bufio.NewReader(loadFile)
	jsonBuf, _ := reader.ReadBytes('\n')

	err = json.Unmarshal(jsonBuf, &header)
	if err != nil {
		return err
	}
	if header.ProtoVersion != 1 {
		return fmt.Errorf("unknown protocol version [%d]", header.ProtoVersion)
	}

	if header.ItemsCount > 0 {
		dlog.Noticef("Loading %d cached responses from [%s]", header.ItemsCount, cacheFilename)

		dec := gob.NewDecoder(reader)

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

		i := 0
		for {
			var savedResponse SavedResponse
			var msg dns.Msg

			dlog.Debugf("== Loading %d response of %d =====================", i+1, header.ItemsCount)

			err = dec.Decode(&savedResponse)
			if err != nil {
				if err == io.EOF {
					break
				}
				return err
			}
			i++

			err = msg.Unpack(savedResponse.Packet)
			if err != nil {
				return err
			}

			cachedResponse := CachedResponse{
				expiration: savedResponse.Expiration,
				msg:        msg,
			}

			if startTime.Before(cachedResponse.expiration) {
				updateTTL(&msg, cachedResponse.expiration)
			}
			//cachedKey := 16
			cachedKey := computeCacheKey(nil, &msg)
			cachedResponses.cache.Add(cachedKey, cachedResponse)

			if savedResponse.Frequent {
				dlog.Debugf("Question is [%s], frequent, expiration date: %s (TTL: %d)", msg.Question[0].Name, savedResponse.Expiration, savedResponse.Expiration.Sub(time.Now())/time.Second)
				cachedResponses.cache.Add(cachedKey, cachedResponse)
			} else {
				dlog.Debugf("Question is [%s], non frequent, expiration date: %s (TTL: %d)", msg.Question[0].Name, savedResponse.Expiration, savedResponse.Expiration.Sub(time.Now())/time.Second)
			}

		}
		dlog.Infof("Loaded %d/%d cached responses in %s", i, header.ItemsCount, time.Now().Sub(startTime))

	}

	return nil
}

func (cachedResponses *CachedResponses) SaveCache(cacheFilename string) (err error) {
	startTime := time.Now()
	cachedResponses.RLock()
	defer cachedResponses.RUnlock()

	if cachedResponses.cache != nil && cachedResponses.cache.Len() > 0 {

		dlog.Noticef("Saving %d cached responses", cachedResponses.cache.Len())

		saveFile, _ := os.Create(cacheFilename)
		defer saveFile.Close()

		saveBuf := bufio.NewWriter(saveFile)
		defer func() {
			ferr := saveBuf.Flush()
			if ferr != nil {
				err = ferr
			}
		}()

		enc := gob.NewEncoder(saveBuf)

		jenc := json.NewEncoder(saveBuf)

		header := CacheFileHeader{
			AppName:          "dnscrypt-proxy-home",
			AppVersion:       AppVersion,
			ProtoVersion:     1,
			TimeSaved:        startTime,
			OriginalLocation: cacheFilename,
			ItemsCount:       cachedResponses.cache.Len(),
			Compressed:       false,
			Description:      "This is a file with saved cache of dnscrypt-proxy-home app. All data after the first line is binary (golang encoding/gob)",
			Links:            []string{"https://github.com/antonme/dnscrypt-proxy-home", "https://github.com/DNSCrypt/dnscrypt-proxy"},
		}

		cachedResponses.RLock()
		defer cachedResponses.RUnlock()

		err = jenc.Encode(header)
		if err != nil {
			return err
		}

		keys := cachedResponses.cache.Keys()
		for keyNum := range keys {
			cacheKey := keys[keyNum].([32]byte)

			cachedAny, _ := cachedResponses.cache.Peek(cacheKey)
			cached := cachedAny.(CachedResponse)
			msg := cached.msg
			msg.Compress = true

			_, valueExist := cachedResponses.fetchLock[cacheKey]

			packet, _ := msg.PackBuffer(nil)

			savedResponse := SavedResponse{
				Expiration: cached.expiration,
				Packet:     packet,
				Frequent:   valueExist,
			}

			err = enc.Encode(&savedResponse)
			if err != nil {
				return err
			}
			dlog.Debug(cached.msg.Question)
			dlog.Debug(cached.expiration)

		}
	} else {
		dlog.Notice("No cache to save")
	}

	dlog.Infof("Time spent saving: %s", time.Now().Sub(startTime))
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
		err := cachedResponses.LoadCache(proxy.cacheFilename, proxy.cacheSize)
		if err != nil {
			dlog.Warnf("Can't load cache from [%s]: %s", proxy.cacheFilename, err)
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
