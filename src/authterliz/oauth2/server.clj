(ns authterliz.oauth2.server
  (:require [clojure.spec :as s]
            [cheshire.core :as json]
            [clojure.string :as str]))

;; server consists of several endpoints
;; * authorization-endpoint - gives authorization code, which could be netatiated for access_token
;; * token-endpoint - provides access_token and jwt
;; * refresh-endpoint - exchange refresh token for next access_token
;; * user-info-endpoint - serves user infromation


;; Parameters sent without a value MUST be treated as if they were
;; omitted from the request.  The authorization server MUST ignore
;; unrecognized request parameters.  Request and response parameters
;; MUST NOT be included more than once.


;; switch flows
;; switch grant_type
;;   authorization_code
;;   password
;;   client_crenetials
;;   implicit
;;   extension....
;; scope contains "openid" turn on openid connect




(defn openid-configuration-response [config]
  {
   :issuer (:base-url config)
   ;;    REQUIRED.  URL using the "https" scheme with no query or fragment
   ;;    component that the OP asserts as its Issuer Identifier.  If Issuer
   ;;    discovery is supported (see Section 2), this value MUST be
   ;;    identical to the issuer value returned by WebFinger.  This also
   ;;    MUST be identical to the "iss" Claim value in ID Tokens issued
   ;;    from this Issuer.


   :authorization_endpoint (str (:base-url config) "/oauth2/authoraize") 
   ;;    REQUIRED.  URL of the OP's OAuth 2.0 Authorization Endpoint
   ;;    [OpenID.Core].


   :token_endpoint (str (:base-url config) "/oauth2/token")
   ;;    URL of the OP's OAuth 2.0 Token Endpoint [OpenID.Core].  This is
   ;;    REQUIRED unless only the Implicit Flow is used.


   :userinfo_endpoint (str (:base-url config) "/oauth2/userinfo")
   ;;    RECOMMENDED.  URL of the OP's UserInfo Endpoint [OpenID.Core].
   ;;    This URL MUST use the "https" scheme and MAY contain port, path,
   ;;    and query parameter components.

   :jwks_uri (str (:base-url config) "/.well-known/jwks.json")
   ;;    REQUIRED.  URL of the OP's JSON Web Key Set [JWK] document.  This
   ;;    contains the signing key(s) the RP uses to validate signatures
   ;;    from the OP.  The JWK Set MAY also contain the Server's encryption
   ;;    key(s), which are used by RPs to encrypt requests to the Server.
   ;;    When both signing and encryption keys are made available, a "use"
   ;;    (Key Use) parameter value is REQUIRED for all keys in the
   ;;    referenced JWK Set to indicate each key's intended usage.
   ;;    Although some algorithms allow the same key to be used for both
   ;;    signatures and encryption, doing so is NOT RECOMMENDED, as it is
   ;;    less secure.  The JWK "x5c" parameter MAY be used to provide X.509
   ;;    representations of keys provided.  When used, the bare key values
   ;;    MUST still be present and MUST match those in the certificate.

   ;; :registration_endpoint ....
   ;;    RECOMMENDED.  URL of the OP's Dynamic Client Registration Endpoint
   ;;    [OpenID.Registration].

   :scopes_supported (concat [:openid :profile :email] (or (:scopes config) []))
   ;;    RECOMMENDED.  JSON array containing a list of the OAuth 2.0
   ;;    [RFC6749] scope values that this server supports.  The server MUST
   ;;    support the "openid" scope value.  Servers MAY choose not to
   ;;    advertise some supported scope values even when this parameter is
   ;;    used, although those defined in [OpenID.Core] SHOULD be listed, if
   ;;    supported.


   :response_types_supported ["code","token","token id_token"]
   ;;    REQUIRED.  JSON array containing a list of the OAuth 2.0
   ;;    "response_type" values that this OP supports.  Dynamic OpenID
   ;;    Providers MUST support the "code", "id_token", and the "token
   ;;    id_token" Response Type values.

   ;; response_modes_supported
   ;;    OPTIONAL.  JSON array containing a list of the OAuth 2.0
   ;;    "response_mode" values that this OP supports, as specified in
   ;;    OAuth 2.0 Multiple Response Type Encoding Practices
   ;;    [OAuth.Responses].  If omitted, the default for Dynamic OpenID
   ;;    Providers is "["query", "fragment"]".


   :grant_types_supported ["authorization_code", "implicit", "password", "client_credentials"]
   ;;    OPTIONAL.  JSON array containing a list of the OAuth 2.0 Grant
   ;;    Type values that this OP supports.  Dynamic OpenID Providers MUST
   ;;    support the "authorization_code" and "implicit" Grant Type values
   ;;    and MAY support other Grant Types.  If omitted, the default value
   ;;    is "["authorization_code", "implicit"]".


   ;; acr_values_supported
   ;;    OPTIONAL.  JSON array containing a list of the Authentication
   ;;    Context Class References that this OP supports.

   ;; subject_types_supported
   ;;    REQUIRED.  JSON array containing a list of the Subject Identifier
   ;;    types that this OP supports.  Valid types include "pairwise" and
   ;;    "public".


   :id_token_signing_alg_values_supported ["RS256"]
   ;;    REQUIRED.  JSON array containing a list of the JWS signing
   ;;    algorithms ("alg" values) supported by the OP for the ID Token to
   ;;    encode the Claims in a JWT [JWT].  The algorithm "RS256" MUST be
   ;;    included.  The value "none" MAY be supported, but MUST NOT be used
   ;;    unless the Response Type used returns no ID Token from the
   ;;    Authorization Endpoint (such as when using the Authorization Code
   ;;    Flow).

   ;; id_token_encryption_alg_values_supported
   ;;    OPTIONAL.  JSON array containing a list of the JWE encryption
   ;;    algorithms ("alg" values) supported by the OP for the ID Token to
   ;;    encode the Claims in a JWT [JWT].

   ;; id_token_encryption_enc_values_supported
   ;;    OPTIONAL.  JSON array containing a list of the JWE encryption
   ;;    algorithms ("enc" values) supported by the OP for the ID Token to
   ;;    encode the Claims in a JWT [JWT].

   ;; userinfo_signing_alg_values_supported
   ;;    OPTIONAL.  JSON array containing a list of the JWS [JWS] signing
   ;;    algorithms ("alg" values) [JWA] supported by the UserInfo Endpoint
   ;;    to encode the Claims in a JWT [JWT].  The value "none" MAY be
   ;;    included.

   ;; userinfo_encryption_alg_values_supported
   ;;    OPTIONAL.  JSON array containing a list of the JWE [JWE]
   ;;    encryption algorithms ("alg" values) [JWA] supported by the
   ;;    UserInfo Endpoint to encode the Claims in a JWT [JWT].

   ;; userinfo_encryption_enc_values_supported
   ;;    OPTIONAL.  JSON array containing a list of the JWE encryption
   ;;    algorithms ("enc" values) [JWA] supported by the UserInfo Endpoint
   ;;    to encode the Claims in a JWT [JWT].

   ;; request_object_signing_alg_values_supported
   ;;    OPTIONAL.  JSON array containing a list of the JWS signing
   ;;    algorithms ("alg" values) supported by the OP for Request Objects,
   ;;    which are described in Section 6.1 of OpenID Connect Core 1.0
   ;;    [OpenID.Core].  These algorithms are used both when the Request
   ;;    Object is passed by value (using the "request" parameter) and when
   ;;    it is passed by reference (using the "request_uri" parameter).
   ;;    Servers SHOULD support "none" and "RS256".

   ;; request_object_encryption_alg_values_supported
   ;;    OPTIONAL.  JSON array containing a list of the JWE encryption
   ;;    algorithms ("alg" values) supported by the OP for Request Objects.
   ;;    These algorithms are used both when the Request Object is passed
   ;;    by value and when it is passed by reference.

   ;; request_object_encryption_enc_values_supported
   ;;    OPTIONAL.  JSON array containing a list of the JWE encryption
   ;;    algorithms ("enc" values) supported by the OP for Request Objects.
   ;;    These algorithms are used both when the Request Object is passed
   ;;    by value and when it is passed by reference.

   :token_endpoint_auth_methods_supported ["client_secret_post" "client_secret_basic"
                                           "client_secret_jwt" "private_key_jwt"]
   ;;    OPTIONAL.  JSON array containing a list of Client Authentication
   ;;    methods supported by this Token Endpoint.  The options are
   ;;    "client_secret_post", "client_secret_basic", "client_secret_jwt",
   ;;    and "private_key_jwt", as described in Section 9 of OpenID Connect
   ;;    Core 1.0 [OpenID.Core].  Other authentication methods MAY be
   ;;    defined by extensions.  If omitted, the default is
   ;;    "client_secret_basic" -- the HTTP Basic Authentication Scheme
   ;;    specified in Section 2.3.1 of OAuth 2.0 [RFC6749].


   ;; token_endpoint_auth_signing_alg_values_supported
   ;;    OPTIONAL.  JSON array containing a list of the JWS signing
   ;;    algorithms ("alg" values) supported by the Token Endpoint for the
   ;;    signature on the JWT [JWT] used to authenticate the Client at the
   ;;    Token Endpoint for the "private_key_jwt" and "client_secret_jwt"
   ;;    authentication methods.  Servers SHOULD support "RS256".  The
   ;;    value "none" MUST NOT be used.

   ;; display_values_supported
   ;;    OPTIONAL.  JSON array containing a list of the "display" parameter
   ;;    values that the OpenID Provider supports.  These values are
   ;;    described in Section 3.1.2.1 of OpenID Connect Core 1.0
   ;;    [OpenID.Core].

   ;; claim_types_supported
   ;;    OPTIONAL.  JSON array containing a list of the Claim Types that
   ;;    the OpenID Provider supports.  These Claim Types are described in
   ;;    Section 5.6 of OpenID Connect Core 1.0 [OpenID.Core].  Values
   ;;    defined by this specification are "normal", "aggregated", and
   ;;    "distributed".  If omitted, the implementation supports only
   ;;    "normal" Claims.

   :claims_supported (concat
                      ["aud",
                       "email",
                       "exp",
                       "family_name",
                       "given_name",
                       "iat",
                       "iss",
                       "locale",
                       "name",
                       "picture",
                       "sub"]

                      (:claims_supported config))
   ;;    RECOMMENDED.  JSON array containing a list of the Claim Names of
   ;;    the Claims that the OpenID Provider MAY be able to supply values
   ;;    for.  Note that for privacy or other reasons, this might not be an
   ;;    exhaustive list.

   ;; :service_documentation url
   ;; TODO autogenerate
   ;;    OPTIONAL.  URL of a page containing human-readable information
   ;;    that developers might want or need to know when using the OpenID
   ;;    Provider.  In particular, if the OpenID Provider does not support
   ;;    Dynamic Client Registration, then information on how to register
   ;;    Clients needs to be provided in this documentation.

   ;; claims_locales_supported
   ;;    OPTIONAL.  Languages and scripts supported for values in Claims
   ;;    being returned, represented as a JSON array of BCP47 [RFC5646]
   ;;    language tag values.  Not all languages and scripts are
   ;;    necessarily supported for all Claim values.

   ;; ui_locales_supported
   ;;    OPTIONAL.  Languages and scripts supported for the user interface,
   ;;    represented as a JSON array of BCP47 [RFC5646] language tag
   ;;    values.

   ;; claims_parameter_supported
   ;;    OPTIONAL.  Boolean value specifying whether the OP supports use of
   ;;    the "claims" parameter, with "true" indicating support.  If
   ;;    omitted, the default value is "false".

   ;; request_parameter_supported
   ;;    OPTIONAL.  Boolean value specifying whether the OP supports use of
   ;;    the "request" parameter, with "true" indicating support.  If
   ;;    omitted, the default value is "false".

   ;; request_uri_parameter_supported
   ;;    OPTIONAL.  Boolean value specifying whether the OP supports use of
   ;;    the "request_uri" parameter, with "true" indicating support.  If
   ;;    omitted, the default value is "true".

   ;; require_request_uri_registration
   ;;    OPTIONAL.  Boolean value specifying whether the OP requires any
   ;;    "request_uri" values used to be pre-registered using the
   ;;    "request_uris" registration parameter.  Pre-registration is
   ;;    REQUIRED when the value is "true".  If omitted, the default value
   ;;    is "false".

   ;; op_policy_uri
   ;;    OPTIONAL.  URL that the OpenID Provider provides to the person
   ;;    registering the Client to read about the OP's requirements on how
   ;;    the Relying Party can use the data provided by the OP.  The
   ;;    registration process SHOULD display this URL to the person
   ;;    registering the Client if it is given.

   ;; op_tos_uri
   ;;    OPTIONAL.  URL that the OpenID Provider provides to the person
   ;;    registering the Client to read about OpenID Provider's terms of
   ;;    service.  The registration process SHOULD display this URL to the
   ;;    person registering the Client if it is given.

   })

(defn json-response [x & [{status :status}]]
  {:body (json/generate-string x)
   :status (or status 200)
   :headers {"Content-Type" "application/json"}})

(defn openid-configuration-endpoint [{cfg :auth/config :as req}]
  (json-response
   (openid-configuration-response cfg)))

(defn authorize-request [{params :params :as req}]
  (let [grant-type (or (:grant_type params) "implicit")]
    (merge params
           {:grant_type (keyword grant-type)
            :scope (when-let [sc (:scope params)] (str/split sc #"\s+"))})))

(defn validate-implicit-request [cfg req]
  (cond-> []
    (nil? (:client_id req))    (conj {:type "invalid_request" :message "client_id parameter is required"})
    (nil? (:redirect_uri req)) (conj {:type "invalid_request" :message "redirect_uri parameter is required"})

    (and
     (:redirect_uri req)
     (:redirect-uri-regex cfg)
     (not (re-matches (:redirect-uri-regex cfg) (:redirect_uri req))))

    (conj {:type "invalid_request" :message (str "invalid redirect_uri")})

    (and
     (:client_id req)
     (:validate-client? cfg)
     (not ((:validate-client? cfg) (:client_id req))))

    (conj {:type "unauthorized_client" :message "invalid client_id"})



    ))

(defn validate-authorize-request [cfg {grant-type :grant_type :as req}]
  (cond
    (= :implicit grant-type) (validate-implicit-request cfg req)
    :else [{:error "Unknown request"}]))

(defn authorize-endpoint [{cfg :auth/config :as req}]
  (let [auth-req (authorize-request req)
        errors (validate-authorize-request cfg auth-req)]
    (if (not (empty? errors))
      (json-response {:error (:type (first errors)) 
                      :errors errors})

      (json-response {:authorize-request auth-req 
                      :errors errors
                      :params (:params req)}))))

(defn token-endpoint [{cfg :auth/config :as req}]
  (json-response {:message "TODO"}))

(defn userinfo-endpoint [{cfg :auth/config :as req}]
  (json-response {:message "TODO"}))

(defn jwt-keys-endpoint [{cfg :auth/config :as req}]
  (json-response {:message "TODO"}))

(defn oauth-server-middleware [h cfg]
  (fn [{uri :uri :as req}]
    (cond
      (= uri "/.well-known/openid-configuration") (openid-configuration-endpoint (assoc req :auth/config cfg))
      (= uri "/oauth2/authorize") (authorize-endpoint (assoc req :auth/config cfg))
      (= uri "/oauth2/token") (authorize-endpoint (assoc req :auth/config cfg))
      (= uri "/oauth2/userinfo") (authorize-endpoint (assoc req :auth/config cfg))
      (= uri "/.well-known/jwks.json") (jwt-keys-endpoint (assoc req :auth/config cfg))
      :else (h req))))



;; (s/def :oauth/authorization-request
;;   (s/keys :req [:oauth.auth-req/responce_type]
;;           :opt [:oauth.auth-req/redirect_uri]))

;; (def authorization-request
;;   {:responce_type {;; Extension response types MAY contain a space-delimited (%x20) list of values
;;                    :desc "The value MUST be one of 'code' for requesting an authorization code as described by [Section 4.1.1], 'token' for requesting an access token (implicit grant) as described by Section 4.2.1, or a registered extension value as described by Section 8.4. Extension response types MAY contain a space-delimited (%x20) list of values"
;;                    :values {:code {:desc "for authorization code"}
;;                             :token {:desc "token - for implicit flow"}}}

;;    :client_id {:desc "client identifier"
;;                :optional true
;;                :type "string"}

;;    :redirect_uri {:desc "If multiple redirection URIs have been registered, if only part of the redirection URI has been registered, or if no redirection URI has been registered, the client MUST include a redirection URI with the authorization request using the \"redirect_uri\" request parameter."
;;                   :type "uri"
;;                   :optional true}
;;    :scope {:desc "The scope of the access request as described by Section 3.3." 
;;            :optional true
           
;;            }
;;    :state {:desc "RECOMMENDED.  An opaque value used by the client to maintain
;;          state between the request and callback.  The authorization
;;          server includes this value when redirecting the user-agent back
;;          to the client.  The parameter SHOULD be used for preventing
;;          cross-site request forgery as described in Section 10.12."
;;            :optional true
;;            :type "string"
;;            }
;;    })


;; (def authorization-response
;;   {
;;    :code {:desc "The authorization code generated by the
;;                  authorization server.  The authorization code MUST expire
;;                  shortly after it is issued to mitigate the risk of leaks.  A
;;                  maximum authorization code lifetime of 10 minutes is
;;                  The client MUST NOT use the authorization code
;;                  more than once.  If an authorization code is used more than
;;                  once, the authorization server MUST deny the request and SHOULD
;;                  revoke (when possible) all tokens previously issued based on
;;                  that authorization code.  The authorization code is bound to
;;                  the client identifier and redirection URI."
;;           :required true}
;;    :state {:desc
;;            "if the \"state\" parameter was present in the client
;;             authorization request.  The exact value received from the
;;             client."
;;            :required true}})

;; (def authorization-error-response
;;   {:error {:type "enum"
;;            :enum {:invalid_request "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed."

;;          :unauthorized_client "The client is not authorized to request an authorization code using this method."

;;          :access_denied "The resource owner or authorization server denied the request."

;;          :unsupported_response_type "The authorization server does not support obtaining an authorization code using this method. "

;;          :invalid_scope "The requested scope is invalid, unknown, or malformed."

;;          :server_error "The authorization server encountered an unexpected
;;                         condition that prevented it from fulfilling the request.
;;                         (This error code is needed because a 500 Internal Server
;;                         Error HTTP status code cannot be returned to the client
;;                         via an HTTP redirect.)" 

;;          :temporarily_unavailable "The authorization server is currently unable to handle
;;                                    the request due to a temporary overloading or maintenance
;;                                    of the server.  (This error code is needed because a 503
;;                                    Service Unavailable HTTP status code cannot be returned
;;                                    to the client via an HTTP redirect.)"}}

;;    :error_description "OPTIONAL.  Human-readable ASCII [USASCII] text providing
;;                       additional information, used to assist the client developer in
;;                       understanding the error that occurred.
;;                       Values for the \"error_description\" parameter MUST NOT include
;;                       characters outside the set %x20-21 / %x23-5B / %x5D-7E."

;;    :error_uri "OPTIONAL.  A URI identifying a human-readable web page with
;;                information about the error, used to provide the client
;;                developer with additional information about the error.
;;                Values for the \"error_uri\" parameter MUST conform to the
;;                URI-reference syntax and thus MUST NOT include characters
;;                outside the set %x21 / %x23-5B / %x5D-7E."

;;    :state  "REQUIRED if a \"state\" parameter was present in the client authorization request.  The exact value received from the client. " })


;; (def authorization-endpoint
;;   {:methods [:get :post]
;;    :request {:params authorization-request}
;;    :response {:success authorization-response
;;               :error authorization-error-response}})

;; (def access-token-request
;;   {:grant_type "REQUIRED.  Value MUST be set to \"authorization_code\". "

;;    :code "REQUIRED.  The authorization code received from the authorization server."

;;    :redirect_uri "REQUIRED, if the \"redirect_uri\" parameter was included in the authorization request as described in Section 4.1.1, and their values MUST be identical."

;;    :client_id "REQUIRED, if the client is not authenticating with the authorization server as described in Section 3.2.1."}
;;   )


;; ;; HTTP/1.1 200 OK
;; ;; Content-Type: application/json;charset=UTF-8
;; ;; Cache-Control: no-store
;; ;; Pragma: no-cache

;; ;; {
;; ;;  "access_token":"2YotnFZFEjr1zCsicMWpAA",
;; ;;  "token_type":"example",
;; ;;  "expires_in":3600,
;; ;;  "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
;; ;;  "example_parameter":"example_value"
;; ;; }

;; (def access-token-response
;;   {:implicit
;;    {:success
;;     {:access_token {}
;;      ;; REQUIRED.  The access token issued by the authorization server.

;;      :token_type {}
;;      ;; REQUIRED.  The type of the token issued as described in
;;      ;; Section 7.1.  Value is case insensitive.

;;      :expires_in {}
;;      ;; RECOMMENDED.  The lifetime in seconds of the access token.  For
;;      ;; example, the value "3600" denotes that the access token will
;;      ;; expire in one hour from the time the response was generated.
;;      ;; If omitted, the authorization server SHOULD provide the
;;      ;; expiration time via other means or document the default value.

;;      :scope {}
;;      ;; OPTIONAL, if identical to the scope requested by the client;
;;      ;; otherwise, REQUIRED.  The scope of the access token as
;;      ;; described by Section 3.3.

;;      :state {}
;;      ;; REQUIRED if the "state" parameter was present in the client
;;      ;; authorization request.  The exact value received from the
;;      ;; client.

;;      ;; The authorization server MUST NOT issue a refresh token.
;;      }
;;     :error {
;;             ;; see errors
;;             }}

;;    ;; Resource Owner Password Credentials Grant
;;    :password
;;    {:request {
;;               ;; grant_type
;;               ;; REQUIRED.  Value MUST be set to "password".

;;               ;; username
;;               ;; REQUIRED.  The resource owner username.

;;               ;; password
;;               ;; REQUIRED.  The resource owner password.

;;               ;; scope
;;               ;; OPTIONAL.  The scope of the access request as described by
;;               ;; Section 3.3.
;;               }
;;     :response {

;;                ;; HTTP/1.1 200 OK
;;                ;; Content-Type: application/json;charset=UTF-8
;;                ;; Cache-Control: no-store
;;                ;; Pragma: no-cache

;;                ;; {
;;                ;;  "access_token":"2YotnFZFEjr1zCsicMWpAA",
;;                ;;  "token_type":"example",
;;                ;;  "expires_in":3600,
;;                ;;  "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
;;                ;;  "example_parameter":"example_value"
;;                ;;  }

;;                }
;;     }


;;    :client_credeintials
;;    ;; A refresh token SHOULD NOT be included.
;;    {:request 
;;               ;; grant_type
;;               ;; REQUIRED.  Value MUST be set to "client_credentials".

;;               ;; scope
;;               ;; OPTIONAL.  The scope of the access request as described by
;;               ;; Section 3.3.

;;     }
;;    :response {

;;               ;; HTTP/1.1 200 OK
;;               ;; Content-Type: application/json;charset=UTF-8
;;               ;; Cache-Control: no-store
;;               ;; Pragma: no-cache

;;               ;; {
;;               ;;  "access_token":"2YotnFZFEjr1zCsicMWpAA",
;;               ;;  "token_type":"example",
;;               ;;  "expires_in":3600,
;;               ;;  "example_parameter":"example_value"
;;               ;;  }
              
;;               }}
;;   :refresh_token
;;   {:request {
;;              ;; grant_type
;;              ;; REQUIRED.  Value MUST be set to "refresh_token".

;;              ;; refresh_token
;;              ;; REQUIRED.  The refresh token issued to the client.

;;              ;; scope
;;              ;; OPTIONAL.  The scope of the access request as described by
;;              ;; Section 3.3.  The requested scope MUST NOT include any scope
;;              ;; not originally granted by the resource owner, and if omitted is
;;              ;; treated as equal to the scope originally granted by the
;;              ;; resource owner.

;;              }}

;;    }
;;   )
