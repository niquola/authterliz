(ns oauth.core
  (:require
   [authterliz.oauth2.server :as oauth]
   [cheshire.core :as json]
   [ring.middleware.defaults :as ring]
   [org.httpkit.server :as srv]))

(defn handler [req]
  {:body "Hello"})

(defn check-credentials [cfg params]
  (cond-> {}
    (not (= "pass" (:password params))) (conj :password "Invalid")
    (not (= "niquola@gmail.com" (:email params))) (conj :email "Invalid")))

(def oauth-config
  {:base-url "http://localhost:5555"
   :redirect-uri-regex #"^http(s)?://localhost.*"
   :check-cridentials check-credentials})

(def app
  (-> handler
      (oauth/oauth-server-middleware  oauth-config)
      (ring/wrap-defaults ring/site-defaults)))

(defonce server (atom nil))

(defn start [port]
  (when-let [s @server] (s))
  (reset! server (srv/run-server #'app {:port port})))

(comment
  (start 5555)

  )
