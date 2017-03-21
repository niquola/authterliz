(ns authterliz.oauth2.core)

;; +--------+                               +---------------+
;; |        |--(A)- Authorization Request ->|   Resource    |
;; |        |                               |     Owner     |
;; |        |<-(B)-- Authorization Grant ---|               |
;; |        |                               +---------------+
;; |        |
;; |        |                               +---------------+
;; |        |--(C)-- Authorization Grant -->| Authorization |
;; | Client |                               |     Server    |
;; |        |<-(D)----- Access Token -------|               |
;; |        |                               +---------------+
;; |        |
;; |        |                               +---------------+
;; |        |--(E)----- Access Token ------>|    Resource   |
;; |        |                               |     Server    |
;; |        |<-(F)--- Protected Resource ---|               |
;; +--------+                               +---------------+

;; An authorization grant is a credential representing the resource
;; owner's authorization (to access its protected resources) used by the
;; client to obtain an access token.  This specification defines four
;; grant types -- authorization code, implicit, resource owner password
;; credentials, and client credentials -- as well as an extensibility
;; mechanism for defining additional types.


;; ## Grant Types

;; * authorization code
;; * implicit
;; * resource owner password credentials
;; * client credentials

;; (def grant-types
;;   {:authorization-code {}
;;    :implicit {}
;;    :owner-password-credentials {}
;;    :client-credentials {}})

;; ;; ## Endpoints

;; ;; *  Authorization endpoint - used by the client to obtain
;; ;;    authorization from the resource owner via user-agent redirection.
;; ;; *  Token endpoint - used by the client to exchange an authorization
;; ;;    grant for an access token, typically with client authentication.
;; ;; *  Redirection endpoint - used by the authorization server to return
;; ;;    responses containing authorization credentials to the client via
;; ;;    the resource owner user-agent.

;; ;; Not every authorization grant type utilizes both endpoints.
;; ;; Extension grant types MAY define additional endpoints as needed.

;; (def end-points
;;   {:authorization {}
;;    :token {}
;;    :redirection {}})

;; (def authtorization-endpoint
;;   {:desc "
;;    The authorization endpoint is used to interact with the resource
;;    owner and obtain an authorization grant.  The authorization server
;;    MUST first verify the identity of the resource owner.  The way in
;;    which the authorization server authenticates the resource owner
;;    (e.g., username and password login, session cookies) is beyond the
;;    scope of this specification."

;;    :tls {:required true}
;;    :methods [:get :post]

;;    :headers {"application/x-www-form-urlencoded"
;;              {:desc "
;;                 See [RFC3986] Section 3.4
;;                 which MUST be retained when adding additional query parameters.  The
;;                 endpoint URI MUST NOT include a fragment component."
;;               }}
;;    :params {:desc "
;;                 Parameters sent without a value MUST be treated as if they were
;;                 omitted from the request.  The authorization server MUST ignore
;;                 unrecognized request parameters.  Request and response parameters
;;                 MUST NOT be included more than once.
;; "
;;             :response_type {:required true
;;                             :type string?
;;                             :enum [:code :token]
;;                             :desc "The value MUST be one of 'code' for requesting an
;;                                    authorization code as described by Section 4.1.1, 'token' for
;;                                    requesting an access token (implicit grant) as described by
;;                                    Section 4.2.1, or a registered extension value as described by
;;                                    Section 8.4.
;;                                    Extension response types MAY contain a space-delimited (%x20) list of
;;                                    values"
;;                             }


;;             ;; If multiple redirection URIs have been registered, if only part of
;;             ;; the redirection URI has been registered, or if no redirection URI has
;;             ;; been registered, the client MUST include a redirection URI with the
;;             ;; authorization request using the "redirect_uri" request parameter.
;;             :redirect_uri {}
;;             :client_id {}
;;             :scope {}
;;             :state {:desc "An opaque value used by the client to maintain
;;                            state between the request and callback.  The authorization
;;                            server includes this value when redirecting the user-agent back
;;                            to the client.  The parameter SHOULD be used for preventing
;;                            cross-site request forgery as described in Section 10.12."}}
;;    :response {:success {
;;                         ;; If an authorization code is used more than
;;                         ;; once, the authorization server MUST deny the request and SHOULD
;;                         ;; revoke (when possible) all tokens previously issued based on
;;                         ;; that authorization code.  The authorization code is bound to
;;                         ;; the client identifier and redirection URI.
;;                         :code {:desc "The authorization code generated by the
;;                             authorization server.  The authorization code MUST expire
;;                             shortly after it is issued to mitigate the risk of leaks.  A
;;                             maximum authorization code lifetime of 10 minutes is
;;                             RECOMMENDED.  The client MUST NOT use the authorization code"}

;;                         :state {:desc "if the "state" parameter was present in the client
;;                              authorization request.  The exact value received from the
;;                              client."}

;;                         ;; HTTP/1.1 302 Found
;;                         ;; Location: https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA
;;                         ;; &state=xyz

;;                         }
;;               :error {

;;                       :error_description {}
;;                       ;; OPTIONAL.  Human-readable ASCII [USASCII] text providing
;;                       ;; additional information, used to assist the client developer in
;;                       ;; understanding the error that occurred.
;;                       ;; Values for the "error_description" parameter MUST NOT include
;;                       ;; characters outside the set %x20-21 / %x23-5B / %x5D-7E.

;;                       :error_uri {}
;;                       ;; OPTIONAL.  A URI identifying a human-readable web page with
;;                       ;; information about the error, used to provide the client
;;                       ;; developer with additional information about the error.
;;                       ;; Values for the "error_uri" parameter MUST conform to the
;;                       ;; URI-reference syntax and thus MUST NOT include characters
;;                       ;; outside the set %x21 / %x23-5B / %x5D-7E.

;;                       :state {}
;;                       ;; REQUIRED if a "state" parameter was present in the client
;;                       ;; authorization request.  The exact value received from the
;;                       ;; client.

;;                       :error {:type :string
;;                               :enum {
;;                                      :invalid_request {}

;;                                      ;; "The request is missing a required parameter, includes an
;;                                      ;; invalid parameter value, includes a parameter more than
;;                                      ;; once, or is otherwise malformed. " 

;;                                      :unauthorized_client {}
;;                                      ;; The client is not authorized to request an authorization
;;                                      ;; code using this method.

;;                                      :access_denied {}
;;                                      ;; The resource owner or authorization server denied the
;;                                      ;; request.

;;                                      :unsupported_response_type {}
;;                                      ;; The authorization server does not support obtaining an
;;                                      ;; authorization code using this method.

;;                                      :invalid_scope {}
;;                                      ;; The requested scope is invalid, unknown, or malformed.

;;                                      :server_error
;;                                      ;; The authorization server encountered an unexpected
;;                                      ;; condition that prevented it from fulfilling the request.
;;                                      ;; (This error code is needed because a 500 Internal Server
;;                                      ;; Error HTTP status code cannot be returned to the client
;;                                      ;; via an HTTP redirect.)

;;                                      :temporarily_unavailable
;;                                      ;; The authorization server is currently unable to handle
;;                                      ;; the request due to a temporary overloading or maintenance
;;                                      ;; of the server.  (This error code is needed because a 503
;;                                      ;; Service Unavailable HTTP status code cannot be returned
;;                                      ;; to the client via an HTTP redirect.)


;;                                      }
;;                               }

;;                       }
;;               }


;;    })

;; ;; Example

;; ;; GET /authorize?response_type=code&client_id=s6BhdRkqt3&state=xyz
;; ;; &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb HTTP/1.1
;; ;; Host: server.example.com

;; (def redirection-endpoint
;;   {:desc "After completing its interaction with the resource owner, the
;;           authorization server directs the resource owner's user-agent back to
;;           the client.  The authorization server redirects the user-agent to the
;;           client's redirection endpoint previously established with the
;;           authorization server during the client registration process or when
;;           making the authorization request.
;;           Which MUST be retained when adding additional query parameters.
;;           The endpoint URI MUST NOT include a fragment component."

;;    :tls :required
;;    :type 'absolute-uri?
;;    :headers {"application/x-www-form-urlencoded" {}}
;;    ;; Lack of a redirection URI registration requirement can enable an
;;    ;; attacker to use the authorization endpoint as an open redirector as
;;    ;; described in Section 10.15.
;;    :validate-redirection-uri fn?

;;    ;; If an authorization request fails validation due to a missing,
;;    ;; invalid, or mismatching redirection URI, the authorization server
;;    ;; SHOULD inform the resource owner of the error and MUST NOT
;;    ;; automatically redirect the user-agent to the invalid redirection URI.

;;    }

;;   )

;; (def token-endpoint
;;   {:desc "The token endpoint is used by the client to obtain an access token by
;;           presenting its authorization grant or refresh token.  The token
;;           endpoint is used with every authorization grant except for the
;;           implicit grant type (since an access token is issued directly)."
;;    :headers {"application/x-www-form-urlencoded" true}
;;    :method [:post]
;;    ;; Parameters sent without a value MUST be treated as if they were
;;    ;; omitted from the request.  The authorization server MUST ignore
;;    ;; unrecognized request parameters.  Request and response parameters
;;    ;; MUST NOT be included more than once.
;;    :params {:client_id {}
;;             :authorization_code {}
;;             :grant_type {:enum ["authorization code"
;;                                 "implicit"
;;                                 "resource owner password credentials"
;;                                 "client credentials"]
;;                          :extensible? true}
;;             :scope {:desc "
;;                           scope       = scope-token *( SP scope-token )
;;                           scope-token = 1*( %x21 / %x23-5B / %x5D-7E )"}
;;             }
;;    })

;; ;; 4.1.  Authorization Code Grant
;; ;; +----------+
;; ;; | Resource |
;; ;; |   Owner  |
;; ;; |          |
;; ;; +----------+
;; ;;      ^
;; ;;      |
;; ;;     (B)
;; ;; +----|-----+          Client Identifier      +---------------+
;; ;; |         -+----(A)-- & Redirection URI ---->|               |
;; ;; |  User-   |                                 | Authorization |
;; ;; |  Agent  -+----(B)-- User authenticates --->|     Server    |
;; ;; |          |                                 |               |
;; ;; |         -+----(C)-- Authorization Code ---<|               |
;; ;; +-|----|---+                                 +---------------+
;; ;;   |    |                                         ^      v
;; ;;  (A)  (C)                                        |      |
;; ;;   |    |                                         |      |
;; ;;   ^    v                                         |      |
;; ;; +---------+                                      |      |
;; ;; |         |>---(D)-- Authorization Code ---------'      |
;; ;; |  Client |          & Redirection URI                  |
;; ;; |         |                                             |
;; ;; |         |<---(E)----- Access Token -------------------'
;; ;; +---------+       (w/ Optional Refresh Token)

;; ;; (s/def :oauth/authorization-request
;; ;;   (s/keys :req [:oauth.auth-req/responce_type]
;; ;;           :opt [:oauth.auth-req/redirect_uri]))

;; ;; (def authorization-request
;; ;;   {:responce_type {;; Extension response types MAY contain a space-delimited (%x20) list of values
;; ;;                    :desc "The value MUST be one of 'code' for requesting an authorization code as described by [Section 4.1.1], 'token' for requesting an access token (implicit grant) as described by Section 4.2.1, or a registered extension value as described by Section 8.4. Extension response types MAY contain a space-delimited (%x20) list of values"
;; ;;                    :values {:code {:desc "for authorization code"}
;; ;;                             :token {:desc "token - for implicit flow"}}}

;; ;;    :client_id {:desc "client identifier"
;; ;;                :optional true
;; ;;                :type "string"}

;; ;;    :redirect_uri {:desc "If multiple redirection URIs have been registered, if only part of the redirection URI has been registered, or if no redirection URI has been registered, the client MUST include a redirection URI with the authorization request using the \"redirect_uri\" request parameter."
;; ;;                   :type "uri"
;; ;;                   :optional true}
;; ;;    :scope {:desc "The scope of the access request as described by Section 3.3." 
;; ;;            :optional true
           
;; ;;            }
;; ;;    :state {:desc "RECOMMENDED.  An opaque value used by the client to maintain
;; ;;          state between the request and callback.  The authorization
;; ;;          server includes this value when redirecting the user-agent back
;; ;;          to the client.  The parameter SHOULD be used for preventing
;; ;;          cross-site request forgery as described in Section 10.12."
;; ;;            :optional true
;; ;;            :type "string"
;; ;;            }
;; ;;    })


;; ;; (def authorization-response
;; ;;   {
;; ;;    :code {:desc "The authorization code generated by the
;; ;;                  authorization server.  The authorization code MUST expire
;; ;;                  shortly after it is issued to mitigate the risk of leaks.  A
;; ;;                  maximum authorization code lifetime of 10 minutes is
;; ;;                  The client MUST NOT use the authorization code
;; ;;                  more than once.  If an authorization code is used more than
;; ;;                  once, the authorization server MUST deny the request and SHOULD
;; ;;                  revoke (when possible) all tokens previously issued based on
;; ;;                  that authorization code.  The authorization code is bound to
;; ;;                  the client identifier and redirection URI."
;; ;;           :required true}
;; ;;    :state {:desc
;; ;;            "if the \"state\" parameter was present in the client
;; ;;             authorization request.  The exact value received from the
;; ;;             client."
;; ;;            :required true}})

;; ;; (def authorization-error-response
;; ;;   {:error {:type "enum"
;; ;;            :enum {:invalid_request "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed."

;; ;;          :unauthorized_client "The client is not authorized to request an authorization code using this method."

;; ;;          :access_denied "The resource owner or authorization server denied the request."

;; ;;          :unsupported_response_type "The authorization server does not support obtaining an authorization code using this method. "

;; ;;          :invalid_scope "The requested scope is invalid, unknown, or malformed."

;; ;;          :server_error "The authorization server encountered an unexpected
;; ;;                         condition that prevented it from fulfilling the request.
;; ;;                         (This error code is needed because a 500 Internal Server
;; ;;                         Error HTTP status code cannot be returned to the client
;; ;;                         via an HTTP redirect.)" 

;; ;;          :temporarily_unavailable "The authorization server is currently unable to handle
;; ;;                                    the request due to a temporary overloading or maintenance
;; ;;                                    of the server.  (This error code is needed because a 503
;; ;;                                    Service Unavailable HTTP status code cannot be returned
;; ;;                                    to the client via an HTTP redirect.)"}}

;; ;;    :error_description "OPTIONAL.  Human-readable ASCII [USASCII] text providing
;; ;;                       additional information, used to assist the client developer in
;; ;;                       understanding the error that occurred.
;; ;;                       Values for the \"error_description\" parameter MUST NOT include
;; ;;                       characters outside the set %x20-21 / %x23-5B / %x5D-7E."

;; ;;    :error_uri "OPTIONAL.  A URI identifying a human-readable web page with
;; ;;                information about the error, used to provide the client
;; ;;                developer with additional information about the error.
;; ;;                Values for the \"error_uri\" parameter MUST conform to the
;; ;;                URI-reference syntax and thus MUST NOT include characters
;; ;;                outside the set %x21 / %x23-5B / %x5D-7E."

;; ;;    :state  "REQUIRED if a \"state\" parameter was present in the client authorization request.  The exact value received from the client. " })


;; ;; (def authorization-endpoint
;; ;;   {:methods [:get :post]
;; ;;    :request {:params authorization-request}
;; ;;    :response {:success authorization-response
;; ;;               :error authorization-error-response}})

;; ;; (def access-token-request
;; ;;   {:grant_type "REQUIRED.  Value MUST be set to \"authorization_code\". "

;; ;;    :code "REQUIRED.  The authorization code received from the authorization server."

;; ;;    :redirect_uri "REQUIRED, if the \"redirect_uri\" parameter was included in the authorization request as described in Section 4.1.1, and their values MUST be identical."

;; ;;    :client_id "REQUIRED, if the client is not authenticating with the authorization server as described in Section 3.2.1."}
;; ;;   )


;; ;; ;; HTTP/1.1 200 OK
;; ;; ;; Content-Type: application/json;charset=UTF-8
;; ;; ;; Cache-Control: no-store
;; ;; ;; Pragma: no-cache

;; ;; ;; {
;; ;; ;;  "access_token":"2YotnFZFEjr1zCsicMWpAA",
;; ;; ;;  "token_type":"example",
;; ;; ;;  "expires_in":3600,
;; ;; ;;  "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
;; ;; ;;  "example_parameter":"example_value"
;; ;; ;; }

;; ;; (def access-token-response
;; ;;   {:implicit
;; ;;    {:success
;; ;;     {:access_token {}
;; ;;      ;; REQUIRED.  The access token issued by the authorization server.

;; ;;      :token_type {}
;; ;;      ;; REQUIRED.  The type of the token issued as described in
;; ;;      ;; Section 7.1.  Value is case insensitive.

;; ;;      :expires_in {}
;; ;;      ;; RECOMMENDED.  The lifetime in seconds of the access token.  For
;; ;;      ;; example, the value "3600" denotes that the access token will
;; ;;      ;; expire in one hour from the time the response was generated.
;; ;;      ;; If omitted, the authorization server SHOULD provide the
;; ;;      ;; expiration time via other means or document the default value.

;; ;;      :scope {}
;; ;;      ;; OPTIONAL, if identical to the scope requested by the client;
;; ;;      ;; otherwise, REQUIRED.  The scope of the access token as
;; ;;      ;; described by Section 3.3.

;; ;;      :state {}
;; ;;      ;; REQUIRED if the "state" parameter was present in the client
;; ;;      ;; authorization request.  The exact value received from the
;; ;;      ;; client.

;; ;;      ;; The authorization server MUST NOT issue a refresh token.
;; ;;      }
;; ;;     :error {
;; ;;             ;; see errors
;; ;;             }}

;; ;;    ;; Resource Owner Password Credentials Grant
;; ;;    :password
;; ;;    {:request {
;; ;;               ;; grant_type
;; ;;               ;; REQUIRED.  Value MUST be set to "password".

;; ;;               ;; username
;; ;;               ;; REQUIRED.  The resource owner username.

;; ;;               ;; password
;; ;;               ;; REQUIRED.  The resource owner password.

;; ;;               ;; scope
;; ;;               ;; OPTIONAL.  The scope of the access request as described by
;; ;;               ;; Section 3.3.
;; ;;               }
;; ;;     :response {

;; ;;                ;; HTTP/1.1 200 OK
;; ;;                ;; Content-Type: application/json;charset=UTF-8
;; ;;                ;; Cache-Control: no-store
;; ;;                ;; Pragma: no-cache

;; ;;                ;; {
;; ;;                ;;  "access_token":"2YotnFZFEjr1zCsicMWpAA",
;; ;;                ;;  "token_type":"example",
;; ;;                ;;  "expires_in":3600,
;; ;;                ;;  "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
;; ;;                ;;  "example_parameter":"example_value"
;; ;;                ;;  }

;; ;;                }
;; ;;     }


;; ;;    :client_credeintials
;; ;;    ;; A refresh token SHOULD NOT be included.
;; ;;    {:request 
;; ;;               ;; grant_type
;; ;;               ;; REQUIRED.  Value MUST be set to "client_credentials".

;; ;;               ;; scope
;; ;;               ;; OPTIONAL.  The scope of the access request as described by
;; ;;               ;; Section 3.3.

;; ;;     }
;; ;;    :response {

;; ;;               ;; HTTP/1.1 200 OK
;; ;;               ;; Content-Type: application/json;charset=UTF-8
;; ;;               ;; Cache-Control: no-store
;; ;;               ;; Pragma: no-cache

;; ;;               ;; {
;; ;;               ;;  "access_token":"2YotnFZFEjr1zCsicMWpAA",
;; ;;               ;;  "token_type":"example",
;; ;;               ;;  "expires_in":3600,
;; ;;               ;;  "example_parameter":"example_value"
;; ;;               ;;  }
              
;; ;;               }}
;; ;;   :refresh_token
;; ;;   {:request {
;; ;;              ;; grant_type
;; ;;              ;; REQUIRED.  Value MUST be set to "refresh_token".

;; ;;              ;; refresh_token
;; ;;              ;; REQUIRED.  The refresh token issued to the client.

;; ;;              ;; scope
;; ;;              ;; OPTIONAL.  The scope of the access request as described by
;; ;;              ;; Section 3.3.  The requested scope MUST NOT include any scope
;; ;;              ;; not originally granted by the resource owner, and if omitted is
;; ;;              ;; treated as equal to the scope originally granted by the
;; ;;              ;; resource owner.

;; ;;              }}

;; ;;    }
;; ;;   )
