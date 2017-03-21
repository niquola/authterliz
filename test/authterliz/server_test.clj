(ns authterliz.oauth2.server-test
  (:require  [clojure.test :refer :all]
             [cheshire.core :as json]
             [matcho.core :as matcho]
             [authterliz.oauth2.server :as subj]))

(def config
  {:base-url "https://localhost:5555"
   :redirect-uri-regex #"^http(s)?://localhost:5555/.*"
   :validate-client?  (fn [cid] (contains? #{"myclient"} cid))
   :authenticate (fn [req])
   :pages {:authenticate (fn [req])
           :error (fn [req errors])
           :switch-account (fn [req errors])}})



(defn handler [req] req)

(def app (subj/oauth-server-middleware handler config))

(defn request [method uri params]
  (let [resp (app {:request-method method
                   :uri uri
                   :params params})]
    (if-let [b (:body resp)]
      (assoc resp :body (json/parse-string b keyword))
      resp)))

(def valid-impl-auth-request
  {:client_id "myclient"
   :redirect_uri "https://localhost:5555/ups#sharp"})

(re-matches
 (:redirect-uri-regex config)
 (:redirect_uri valid-impl-auth-request))

(deftest implicit-test
  (matcho/match
   (request :get "/oauth2/authorize" {})
   {:body {:error "invalid_request"
           :errors #(not (empty? %))}})

  (matcho/match
   (request :get "/oauth2/authorize" valid-impl-auth-request)
   {:status 200
    :body {:error nil?
           :errors #(or (nil? %) (empty? %))}})

  (matcho/match
   (request :get "/oauth2/authorize" (assoc valid-impl-auth-request :redirect_uri "wrong"))
   {:status 200
    :body {:error "invalid_request"
           :errors [{:type "invalid_request", :message "invalid redirect_uri"}]}})

  (matcho/match
   (request :get "/oauth2/authorize" (assoc valid-impl-auth-request :client_id "wrong-client"))
   {:status 200
    :body {:error "unauthorized_client"
           :errors [{:type "unauthorized_client", :message "invalid client_id"}]}})



  )

