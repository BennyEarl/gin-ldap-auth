package basicldap


import (
  "net/http"
  "os"
  "strings"
  "strconv"
  "time"
  "encoding/base64"
  "log"

  "github.com/gin-gonic/gin"
  "github.com/shaj13/libcache"
  _ "github.com/shaj13/libcache/fifo"
  "github.com/shaj13/go-guardian/auth"
  "github.com/shaj13/go-guardian/auth/strategies/ldap"

)

var strategy auth.Strategy
var cacheObj libcache.Cache

func loadEnvVars(cfg *ldap.Config) *ldap.Config {
  var exists bool

  cfg.BaseDN, exists  = os.LookupEnv("BASEDN")
  cfg.BindDN, exists  = os.LookupEnv("BINDND")
  cfg.Host, exists    = os.LookupEnv("HOST")
  cfg.Filter, exists  = os.LookupEnv("FILTER")
  cfg.BindPassword, exists     = os.LookupEnv("BINDPASSWORD")

  if !exists {
    log.Fatalf("Error loading ldap config from environment")
  }
  return cfg
}

func Auth (ttl time.Duration) gin.HandlerFunc {
  ldapInit(ttl)
  return func(c *gin.Context) {
    auth := strings.SplitN(c.Request.Header.Get("Authorization"), " ", 2)
    var realm string
    if realm == "" {
        realm = "Authorization Required"
    }
    realm = "Basic realm=" + strconv.Quote(realm)

    if len(auth) != 2 || auth[0] != "Basic" {
      c.Header("WWW-Authenticate", realm)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
    }
    payload, _ := base64.StdEncoding.DecodeString(auth[1])
    pair := strings.SplitN(string(payload), ":", 2)

    if len(pair) != 2 || !ldapAuth(c) {
      c.Header("WWW-Authenticate", realm)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
    }

    c.Next()
  }
}

func ldapInit(ttl time.Duration) {
  cfg := &ldap.Config{
    Port: "389",
  }
  cfg = loadEnvVars(cfg)
	cacheObj = libcache.FIFO.New(0)
	cacheObj.SetTTL(time.Minute * ttl)
	cacheObj.RegisterOnExpired(func(key, _ interface{}) {
		cacheObj.Peek(key)
	})
	strategy = ldap.NewCached(cfg, cacheObj)
}

func ldapAuth(c *gin.Context) bool {
	_, err := strategy.Authenticate(c, c.Request)
	if err != nil {
    return false
	}
  log.Println(err)
  return true
}
