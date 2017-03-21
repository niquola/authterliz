# Authterliz

A Clojure library (with some inversion of control :() to implement 
OAuth 2.0 & OpenId connect server/clients.


## Usage

```
(def oauth-config
  {:base-url "http://localhost:5555"
   :valid-client? validate-client-fn
   :redirect-uri-regex #"^localhost:5555/.*" })

(-> handler
  ...
  (oauth/oauth-server-middleware oauth-config)
  ...
  )

```

## License

Copyright © 2017 niquola

Distributed under the Eclipse Public License either version 1.0 or (at
your option) any later version.
