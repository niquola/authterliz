(ns authterliz.oauth2.server.ui
  (:require [hiccup.core :as hiccup]
            [garden.core :as gcss]
            [ring.util.anti-forgery :as anti-forgery]))

(def style
  (gcss/css
   [:body {:padding "20px"
           :background-color "#1f1f24"}
    [:form.login-form
     {:margin "4em auto 4em"
      :width "300px"
      :box-shadow "0px 0px 4px black"
      :background-color "white"
      :border-radius "4px"
      :padding "20px 40px"}
     [:h3 {:margin 0 :line-height "2.5em"}]
     [:button.submit {:display "block"
                      :padding "10px"
                      :background-color "#db5e36"
                      :color "white"
                      :font-weight "bold"
                      :width "100%"
                      :border "none"}]]]))

(defn layout [cfg content]
  (hiccup/html
   [:html
    [:head
     [:title "OAuth2.0/OpenId Connect"]
     [:link {:href "//maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css"
             :rel "stylesheet"}]
     [:style style]]
    [:body [:div.auth-body content]]]))

(defn authenticate-page [{cfg :auth/config :as req}]
  {:headers {"Content-Type" "text/html"}
   :body  (layout
           cfg
           [:form.form.login-form {:method "POST"
                                   :action (str  "/oauth2/signin?"  (:query-string req))}
            [:h3 "Sign In"]
            (anti-forgery/anti-forgery-field)
            (when-let [err (:errors req)] [:pre (pr-str err)])
            [:input.form-control {:required true
                                  :type "email" :name "email" :placeholder "Email"}]
            [:br]
            [:input.form-control {:required true
                                  :type "password" :name "password" :placeholder "Password"}]
            [:br]
            [:a {:href "#"} "Forgot password"]
            [:br]
            [:br]
            [:button.submit {} "Submit"]])})

(defn errors-page [{cfg :auth/config :as req} errors]
  {:headers {"Content-Type" "text/html"}
   :body  (layout  cfg [:div.errors [:h3 "Errors"] [:pre (pr-str errors)]])})

(defn signup-page [{cfg :auth/config :as req}])
