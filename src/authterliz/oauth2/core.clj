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

(def grant-types
  {:authorization-code {}
   :implicit {}
   :owner-password-credentials {}
   :client-credentials {}})

;; ## Endpoints

;; *  Authorization endpoint - used by the client to obtain
;;    authorization from the resource owner via user-agent redirection.
;; *  Token endpoint - used by the client to exchange an authorization
;;    grant for an access token, typically with client authentication.
;; *  Redirection endpoint - used by the authorization server to return
;;    responses containing authorization credentials to the client via
;;    the resource owner user-agent.

;; Not every authorization grant type utilizes both endpoints.
;; Extension grant types MAY define additional endpoints as needed.

(def end-points
  {:authorization {}
   :token {}
   :redirection {}})

(def authtorization-endpoint
  {:desc "
   The authorization endpoint is used to interact with the resource
   owner and obtain an authorization grant.  The authorization server
   MUST first verify the identity of the resource owner.  The way in
   which the authorization server authenticates the resource owner
   (e.g., username and password login, session cookies) is beyond the
   scope of this specification."

   :tls {:required true}
   :methods [:get :post]

   :headers {"application/x-www-form-urlencoded"
             {:desc "
                See [RFC3986] Section 3.4
                which MUST be retained when adding additional query parameters.  The
                endpoint URI MUST NOT include a fragment component."
              }}
   :params {:desc "
                Parameters sent without a value MUST be treated as if they were
                omitted from the request.  The authorization server MUST ignore
                unrecognized request parameters.  Request and response parameters
                MUST NOT be included more than once.
"
            :response_type {:required true
                            :type string?
                            :enum [:code :token]
                            :desc "The value MUST be one of 'code' for requesting an
                                   authorization code as described by Section 4.1.1, 'token' for
                                   requesting an access token (implicit grant) as described by
                                   Section 4.2.1, or a registered extension value as described by
                                   Section 8.4.
                                   Extension response types MAY contain a space-delimited (%x20) list of
                                   values"
                            }


            ;; If multiple redirection URIs have been registered, if only part of
            ;; the redirection URI has been registered, or if no redirection URI has
            ;; been registered, the client MUST include a redirection URI with the
            ;; authorization request using the "redirect_uri" request parameter.
            :redirect_uri {}
            :client_id {}
            :scope {}
            :state {:desc "An opaque value used by the client to maintain
                           state between the request and callback.  The authorization
                           server includes this value when redirecting the user-agent back
                           to the client.  The parameter SHOULD be used for preventing
                           cross-site request forgery as described in Section 10.12."}}
   :response {:success {
                        ;; If an authorization code is used more than
                        ;; once, the authorization server MUST deny the request and SHOULD
                        ;; revoke (when possible) all tokens previously issued based on
                        ;; that authorization code.  The authorization code is bound to
                        ;; the client identifier and redirection URI.
                        :code {:desc "The authorization code generated by the
                            authorization server.  The authorization code MUST expire
                            shortly after it is issued to mitigate the risk of leaks.  A
                            maximum authorization code lifetime of 10 minutes is
                            RECOMMENDED.  The client MUST NOT use the authorization code"}

                        :state {:desc "if the "state" parameter was present in the client
                             authorization request.  The exact value received from the
                             client."}

                        ;; HTTP/1.1 302 Found
                        ;; Location: https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA
                        ;; &state=xyz

                        }
              :error {

                      :error_description {}
                      ;; OPTIONAL.  Human-readable ASCII [USASCII] text providing
                      ;; additional information, used to assist the client developer in
                      ;; understanding the error that occurred.
                      ;; Values for the "error_description" parameter MUST NOT include
                      ;; characters outside the set %x20-21 / %x23-5B / %x5D-7E.

                      :error_uri {}
                      ;; OPTIONAL.  A URI identifying a human-readable web page with
                      ;; information about the error, used to provide the client
                      ;; developer with additional information about the error.
                      ;; Values for the "error_uri" parameter MUST conform to the
                      ;; URI-reference syntax and thus MUST NOT include characters
                      ;; outside the set %x21 / %x23-5B / %x5D-7E.

                      :state {}
                      ;; REQUIRED if a "state" parameter was present in the client
                      ;; authorization request.  The exact value received from the
                      ;; client.

                      :error {:type :string
                              :enum {
                                     :invalid_request {}

                                     ;; "The request is missing a required parameter, includes an
                                     ;; invalid parameter value, includes a parameter more than
                                     ;; once, or is otherwise malformed. " 

                                     :unauthorized_client {}
                                     ;; The client is not authorized to request an authorization
                                     ;; code using this method.

                                     :access_denied {}
                                     ;; The resource owner or authorization server denied the
                                     ;; request.

                                     :unsupported_response_type {}
                                     ;; The authorization server does not support obtaining an
                                     ;; authorization code using this method.

                                     :invalid_scope {}
                                     ;; The requested scope is invalid, unknown, or malformed.

                                     :server_error
                                     ;; The authorization server encountered an unexpected
                                     ;; condition that prevented it from fulfilling the request.
                                     ;; (This error code is needed because a 500 Internal Server
                                     ;; Error HTTP status code cannot be returned to the client
                                     ;; via an HTTP redirect.)

                                     :temporarily_unavailable
                                     ;; The authorization server is currently unable to handle
                                     ;; the request due to a temporary overloading or maintenance
                                     ;; of the server.  (This error code is needed because a 503
                                     ;; Service Unavailable HTTP status code cannot be returned
                                     ;; to the client via an HTTP redirect.)


                                     }
                              }

                      }
              }


   })

;; Example

;; GET /authorize?response_type=code&client_id=s6BhdRkqt3&state=xyz
;; &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb HTTP/1.1
;; Host: server.example.com

(def redirection-endpoint
  {:desc "After completing its interaction with the resource owner, the
          authorization server directs the resource owner's user-agent back to
          the client.  The authorization server redirects the user-agent to the
          client's redirection endpoint previously established with the
          authorization server during the client registration process or when
          making the authorization request.
          Which MUST be retained when adding additional query parameters.
          The endpoint URI MUST NOT include a fragment component."

   :tls :required
   :type 'absolute-uri?
   :headers {"application/x-www-form-urlencoded" {}}
   ;; Lack of a redirection URI registration requirement can enable an
   ;; attacker to use the authorization endpoint as an open redirector as
   ;; described in Section 10.15.
   :validate-redirection-uri fn?

   ;; If an authorization request fails validation due to a missing,
   ;; invalid, or mismatching redirection URI, the authorization server
   ;; SHOULD inform the resource owner of the error and MUST NOT
   ;; automatically redirect the user-agent to the invalid redirection URI.

   }

  )

(def token-endpoint
  {:desc "The token endpoint is used by the client to obtain an access token by
          presenting its authorization grant or refresh token.  The token
          endpoint is used with every authorization grant except for the
          implicit grant type (since an access token is issued directly)."
   :headers {"application/x-www-form-urlencoded" true}
   :method [:post]
   ;; Parameters sent without a value MUST be treated as if they were
   ;; omitted from the request.  The authorization server MUST ignore
   ;; unrecognized request parameters.  Request and response parameters
   ;; MUST NOT be included more than once.
   :params {:client_id {}
            :authorization_code {}
            :grant_type {:enum ["authorization code"
                                "implicit"
                                "resource owner password credentials"
                                "client credentials"]
                         :extensible? true}
            :scope {:desc "
                          scope       = scope-token *( SP scope-token )
                          scope-token = 1*( %x21 / %x23-5B / %x5D-7E )"}
            }
   })

;; 4.1.  Authorization Code Grant
;; +----------+
;; | Resource |
;; |   Owner  |
;; |          |
;; +----------+
;;      ^
;;      |
;;     (B)
;; +----|-----+          Client Identifier      +---------------+
;; |         -+----(A)-- & Redirection URI ---->|               |
;; |  User-   |                                 | Authorization |
;; |  Agent  -+----(B)-- User authenticates --->|     Server    |
;; |          |                                 |               |
;; |         -+----(C)-- Authorization Code ---<|               |
;; +-|----|---+                                 +---------------+
;;   |    |                                         ^      v
;;  (A)  (C)                                        |      |
;;   |    |                                         |      |
;;   ^    v                                         |      |
;; +---------+                                      |      |
;; |         |>---(D)-- Authorization Code ---------'      |
;; |  Client |          & Redirection URI                  |
;; |         |                                             |
;; |         |<---(E)----- Access Token -------------------'
;; +---------+       (w/ Optional Refresh Token)
