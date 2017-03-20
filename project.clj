(defproject authterliz "0.1.0-SNAPSHOT"
  :description "FIXME: write description"
  :url "http://example.com/FIXME"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}

  :dependencies [[org.clojure/clojure "1.9.0-alpha15"]
                 [clj-time "0.12.2"]
                 [cheshire "5.6.3"]
                 [ring/ring-core "1.5.0"]
                 [http-kit "2.2.0"] 
                 [ring/ring-defaults "0.2.3"]
                 [clj-jwt "0.1.1" :exclusions [joda-time]]])
