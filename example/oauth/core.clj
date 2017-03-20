(ns oauth.core
  (:require
   [authterliz.oauth2.server :as oauth]
   [cheshire.core :as json]
   [ring.middleware.defaults :as ring]
   [org.httpkit.server :as srv]))

(defn handler [req]
  {:body "Hello"})

(def oauth-config
  {:base-url "http://localhost:5555"
   :redirect-uri-regex #"^localhost:5555/.*"
   })

(def app
  (ring/wrap-defaults 
   (oauth/oauth-server-middleware handler oauth-config)
   ring/site-defaults))

(defonce server (atom nil))

(defn start [port]
  (when-let [s @server] (s))
  (reset! server (srv/run-server #'app {:port port})))

(comment
  (start 5555)

  )
