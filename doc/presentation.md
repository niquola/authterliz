# Authentication, Authorization & Identity Management in distributed systems


## Problem Statement


```
  User <-> System
  
  Users <-> System (Authentication & Access Control)
  
  Users <-> Clients <-> System

  Users <-> Clients <-> Systems (Identity Management, Access Control)
```

## Example:

Development environment.

* Issue/Bug Tracker
* CI travis
* CD 
* SCM github or what ever
* Infrastructure

Our example:

* fingerprint login (OpenID)

Your examples?


## History:

* LDAP/Active Directory
* Linux PAM
* OAuth 2.0 & OpenID etc (API epoch)


## Set of standards

### (OAuth2.0)[https://oauth.net/2/]

OAuth 2.0 is the industry-standard protocol for authorization. 
2.0 focuses on client developer simplicity while providing specific
authorization flows for web applications, desktop applications, mobile phones,
and living room devices.

CORE:

* OAuth 2.0 Framework - RFC 6749
* Bearer Token Usage - RFC 6750
* Threat Model and Security Considerations - RFC 6819

Extensions

* OAuth 2.0 Device Flow
* OAuth 2.0 Token Introspection - RFC 7662, to determine the active state and meta-information of a token
* PKCE - Proof Key for Code Exchange, better security for native apps
* Native Apps - Recommendations for using OAuth 2.0 with native apps
* JSON Web Token - RFC 7519
* OAuth Assertions Framework - RFC 7521
* SAML2 Bearer Assertion - RFC 7522, for integrating with existing identity systems
* JWT Bearer Assertion - RFC 7523, for integrating with existing identity systems

### (OpenID)[http://openid.net/connect/]

OpenID Connect 1.0 is a simple identity layer on top of the OAuth 2.0 protocol.
It allows Clients to verify the identity of the End-User based on the
authentication performed by an Authorization Server, as well as to obtain basic
profile information about the End-User in an interoperable and REST-like manner.


* The OpenID Connect 1.0 specification consists of these documents:
* Core – Defines the core OpenID Connect functionality: authentication built on top of OAuth 2.0 and the use of Claims to communicate information about the End-User
* Discovery – (Optional) Defines how Clients dynamically discover information about OpenID Providers
* Dynamic Registration – (Optional) Defines how clients dynamically register with OpenID Providers
* OAuth 2.0 Multiple Response Types – Defines several specific new OAuth 2.0 response types
* OAuth 2.0 Form Post Response Mode – (Optional) Defines how to return OAuth 2.0 Authorization Response parameters (including OpenID Connect Authentication Response parameters) using HTML form values that are auto-submitted by the User Agent using HTTP POST
* Session Management – (Optional) Defines how to manage OpenID Connect sessions, including postMessage-based logout functionality
* Front-Channel Logout – (Optional) Defines a front-channel logout mechanism that does not use an OP iframe on RP pages
* Back-Channel Logout – (Optional) Defines a logout mechanism that uses direct back-channel communication between the OP and RPs being logged out
 
 
### OAuth2.0


```
     +--------+                               +---------------+
     |        |--(A)- Authorization Request ->|   Resource    |
     |        |                               |     Owner     |
     |        |<-(B)-- Authorization Grant ---|               |
     |        |                               +---------------+
     |        |
     |        |                               +---------------+
     |        |--(C)-- Authorization Grant -->| Authorization |
     | Client |                               |     Server    |
     |        |<-(D)----- Access Token -------|               |
     |        |                               +---------------+
     |        |
     |        |                               +---------------+
     |        |--(E)----- Access Token ------>|    Resource   |
     |        |                               |     Server    |
     |        |<-(F)--- Protected Resource ---|               |
     +--------+                               +---------------+
     
     
     
     Implicite flow (SPA application):

     +----------+
     | Resource |
     |  Owner   |
     |          |
     +----------+
          ^
          |
         (B)
     +----|-----+          Client Identifier     +---------------+
     |         -|----(A)-- & Redirection URI --->|               |
     |  User-   |                                | Authorization |
     |  Agent  -|----(B)-- User authenticates -->|     Server    |
     |          |                                |               |
     |          |<---(C)--- Redirection URI ----<|               |
     |          |          with Access Token     +---------------+
     |          |            in Fragment
     |          |                                +---------------+
     |          |----(D)--- Redirection URI ---->|   Web-Hosted  |
     |          |          without Fragment      |     Client    |
     |          |                                |    Resource   |
     |     (F)  |<---(E)------- Script ---------<|               |
     |          |                                +---------------+
     +-|--------+
       |    |
      (A)  (G) Access Token
       |    |
       ^    v
     +---------+
     |         |
     |  Client |
     |         |
     +---------+
     
     Resource Owner Password Credentials Grant (Mobile, Desktop)
     
     +----------+
     | Resource |
     |  Owner   |
     |          |
     +----------+
          v
          |    Resource Owner
         (A) Password Credentials
          |
          v
     +---------+                                  +---------------+
     |         |>--(B)---- Resource Owner ------->|               |
     |         |         Password Credentials     | Authorization |
     | Client  |                                  |     Server    |
     |         |<--(C)---- Access Token ---------<|               |
     |         |    (w/ Optional Refresh Token)   |               |
     +---------+                                  +---------------+ 
     
```

### Flows

* Authorization Code
* Implicit
* Resource Owner Password Credentials
* Client Credentials 



### Authorization Request

* response_type:  REQUIRED.  Value MUST be set to "code".
* client_id: REQUIRED.  The client identifier
* redirect_uri: OPTIONAL.
* scope: OPTIONAL.
* state: RECOMMENDED.  An opaque value used by the client to maintain state between the request and callback.  

```
GET /authorize?response_type=code&client_id=s6BhdRkqt3&state=xyz
        &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb HTTP/1.1
Host: server.example.com

```

### Authorization Response

* code:  REQUIRED.  The authorization code generated by the authorization server.
* state: REQUIRED.   if the "state" parameter was present in the client authorization request.

```
HTTP/1.1 302 Found
Location: https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA &state=xyz
```

### Error Response

error
  * invalid_request
  * unauthorized_client
  * access_denied
  * unsupported_response_type
  * invalid_scope
  * server_error
  * temporarily_unavailable
...


### Access Token Request

* grant_type: REQUIRED.  Value MUST be set to "authorization_code".
* code: REQUIRED.  The authorization code received from the authorization server.
* redirect_uri: REQUIRED, if the "redirect_uri" parameter was included in the authorization request
* client_id: REQUIRED, if the client is not authenticating with the authorization

````
POST /token HTTP/1.1
Host: server.example.com
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA
&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
````

### Access Token Response


```
HTTP/1.1 200 OK
Content-Type: application/json;charset=UTF-8
Cache-Control: no-store
Pragma: no-cache

{
  "access_token":"2YotnFZFEjr1zCsicMWpAA",
  "token_type":"example",
  "expires_in":3600,
  "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
  "example_parameter":"example_value"
}
```

## Attacks

### Phishing Attacks

Wide deployment of this and similar protocols may cause end-users to
become inured to the practice of being redirected to websites where
they are asked to enter their passwords.  If end-users are not
careful to verify the authenticity of these websites before entering
their credentials, it will be possible for attackers to exploit this
practice to steal resource owners' passwords.

End-user to verify the authenticity of the authorization server!!! For Example TLS

### Cross-Site Request Forgery

Cross-site request forgery (CSRF) is an exploit in which an attacker
causes the user-agent of a victim end-user to follow a malicious URI
(e.g., provided to the user-agent as a misleading link, image, or
redirection) to a trusting server (usually established via the
presence of a valid session cookie).

A CSRF attack against the client's redirection URI allows an attacker
to inject its own authorization code or access token, which can
result in the client using an access token associated with the
attacker's protected resources rather than the victim's (e.g., save
the victim's bank account information to a protected resource
controlled by the attacker).

```
Привет, Алиса! Посмотри, какой милый котик: <img src="http://bank.example.com/withdraw?account=Alice&amount=1000000&for=Mallory">]
```

* state parameter in OAuth0

### Clickjacking

In a clickjacking attack, an attacker registers a legitimate client
and then constructs a malicious site in which it loads the
authorization server's authorization endpoint web page in a
transparent iframe overlaid on top of a set of dummy buttons, which
are carefully constructed to be placed directly under important
buttons on the authorization page.  When an end-user clicks a
misleading visible button, the end-user is actually clicking an
invisible button on the authorization page (such as an "Authorize"
button).  This allows an attacker to trick a resource owner into
granting its client access without the end-user's knowledge.

To prevent this form of attack, native applications SHOULD use
external browsers instead of embedding browsers within the
application when requesting end-user authorization.  For most newer
browsers, avoidance of iframes can be enforced by the authorization
server using the (non-standard) "x-frame-options" header.  This
header can have two values, "deny" and "sameorigin", which will block
any framing, or framing by sites with a different origin,
respectively.  For older browsers, JavaScript frame-busting
techniques can be used but may not be effective in all browsers.

Существует более жёсткий вариант предыдущего механизма, в котором с каждым
действием ассоциируется уникальный одноразовый ключ.



### Open Redirectors

The authorization server, authorization endpoint, and client
redirection endpoint can be improperly configured and operate as open
redirectors.  An open redirector is an endpoint using a parameter to
automatically redirect a user-agent to the location specified by the
parameter value without any validation.


## Bearer Token Spec [https://tools.ietf.org/html/rfc6750]

This specification describes how to use bearer tokens in HTTP
requests to access OAuth 2.0 protected resources.  Any party in
possession of a bearer token (a "bearer") can use it to get access to
the associated resources (without demonstrating possession of a
cryptographic key).  To prevent misuse, bearer tokens need to be
protected from disclosure in storage and in transport.

### Bearer Token

A security token with the property that any party in possession of
the token (a "bearer") can use the token in any way that any other
party in possession of it can.  Using a bearer token does not
require a bearer to prove possession of cryptographic key material
(proof-of-possession).

* header
* uri
* form encoded


## JSON Web Token

JSON Web Token (JWT) is an open standard (RFC 7519) that defines a compact and
self-contained way for securely transmitting information between parties as a
JSON object. This information can be verified and trusted because it is
digitally signed. JWTs can be signed using a secret (with the HMAC algorithm) or
a public/private key pair using RSA.

*Authentication*: This is the most common scenario for using JWT. Once the user is
logged in, each subsequent request will include the JWT, allowing the user to
access routes, services, and resources that are permitted with that token.
Single Sign On is a feature that widely uses JWT nowadays, because of its small
overhead and its ability to be easily used across different domains.

*Information Exchange*: JSON Web Tokens are a good way of securely transmitting
information between parties, because as they can be signed, for example using
public/private key pairs, you can be sure that the senders are who they say they
are. Additionally, as the signature is calculated using the header and the
payload, you can also verify that the content hasn't been tampered with.


```
xxxxx.yyyyy.zzzzz

all parts are base64 encoded

xxx - header
yyy - payload
zzz - signature

Header:

{
  "alg": "HS256",
  "typ": "JWT"
}

Payload:

{
  "sub": "1234567890",
  "name": "John Doe",
  "admin": true
}

Signature:

HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  secret)
  
```

Example:  [https://jwt.io/]

Standard claims:

* "iss" (Issuer)
* "sub" (Subject)
* "aud" (Audience)
* "exp" (Expiration Time)
* "nbf" (Not Before)
* "iat" (Issued At)
* "jti" (JWT ID)

Public registered claims [https://www.iana.org/assignments/jwt/jwt.xhtml] by
IANA (от англ. Internet Assigned Numbers Authority — «Администрация адресного
пространства Интернет») — функция управления пространствами IP-адресов, доменов
верхнего уровня, а также регистрирующая типы данных MIME и параметры прочих
протоколов Интернета.


## OpenID Connect

OpenID Connect 1.0 is a simple identity layer on top of the OAuth 2.0 [RFC6749]
protocol. It enables Clients to verify the identity of the End-User based on the
authentication performed by an Authorization Server, as well as to obtain basic
profile information about the End-User in an interoperable and REST-like manner.

OpenID Connect implements authentication as an extension to the OAuth 2.0
authorization process. Use of this extension is requested by Clients by
including the openid scope value in the Authorization Request. Information about
the authentication performed is returned in a JSON Web Token (JWT) [JWT] called
an ID Token (see Section 2).

* The RP (Client) sends a request to the OpenID Provider (OP).
* The OP authenticates the End-User and obtains authorization.
* The OP responds with an ID Token and usually an Access Token.
* The RP can send a request with the Access Token to the UserInfo Endpoint.
* The UserInfo Endpoint returns Claims about the End-User.
* These steps are illustrated in the following diagram:


```
  +--------+                                   +--------+
  |        |                                   |        |
  |        |---------(1) AuthN Request-------->|        |
  |        |                                   |        |
  |        |  +--------+                       |        |
  |        |  |        |                       |        |
  |        |  |  End-  |<--(2) AuthN & AuthZ-->|        |
  |        |  |  User  |                       |        |
  |   RP   |  |        |                       |   OP   |
  |        |  +--------+                       |        |
  |        |                                   |        |
  |        |<--------(3) AuthN Response--------|        |
  |        |                                   |        |
  |        |---------(4) UserInfo Request----->|        |
  |        |                                   |        |
  |        |<--------(5) UserInfo Response-----|        |
  |        |                                   |        |
  +--------+                                   +--------+
```

Extension of OAuth2.0

Auth Request:

* scope REQUIRED. OpenID Connect requests MUST contain the *openid* scope value. 
* nonce OPTIONAL. String value used to associate a Client session with an ID Token, and to mitigate replay attacks. 
* display OPTIONAL. ASCII string value that specifies how the Authorization
  Server displays the authentication and consent user interface pages to the
  End-User.
  *  *page*  with a full User Agent page view.
  *  *popup* with a popup User Agent window. 
  *  *touch* with a device that leverages a touch interface.
* prompt OPTIONAL. whether prompts the End-User for reauthentication and consent. The defined values are:
  * none    MUST NOT display any authentication or consent user interface pages. An error is returned if an End-User is not already authenticated or the Client does not have pre-configured consent for the requested Claims or does not fulfill other conditions for processing the request. The error code will typically be login_required, interaction_required, or another code defined in Section 3.1.2.6. This can be used as a method to check for existing authentication and/or consent.
  * login   SHOULD prompt the End-User for reauthentication. 
  * consent SHOULD prompt the End-User for consent before returning information to the Client.
  * select_account prompt the End-User to select a user account. This enables an End-User who has multiple accounts at the Authorization Server to select amongst the multiple accounts that they might have current sessions for. If it cannot obtain an account selection choice made by the End-User, it MUST return an error, typically account_selection_required.

```
AUTH REQUEST

HTTP/1.1 302 Found
Location: https://server.example.com/authorize?
  response_type=code
  &scope=openid%20profile%20email
  &client_id=s6BhdRkqt3
  &state=af0ifjsldkj
  &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
  
RESP:

HTTP/1.1 302 Found
Location: https://client.example.org/cb?
  code=SplxlOBeZQQYbYS6WxSbIA
  &state=af0ifjsldkj  
    
TOKEN REQUEST:

POST /token HTTP/1.1
Host: server.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA
  &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb    

RESP:

HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store
Pragma: no-cache

{
  "access_token": "SlAV32hkKG",
  "token_type": "Bearer",
  "refresh_token": "8xLOxBtZp8",
  "expires_in": 3600,
  "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjFlOWdkazcifQ.ewogImlzc
    yI6ICJodHRwOi8vc2VydmVyLmV4YW1wbGUuY29tIiwKICJzdWIiOiAiMjQ4Mjg5
    NzYxMDAxIiwKICJhdWQiOiAiczZCaGRSa3F0MyIsCiAibm9uY2UiOiAibi0wUzZ
    fV3pBMk1qIiwKICJleHAiOiAxMzExMjgxOTcwLAogImlhdCI6IDEzMTEyODA5Nz
    AKfQ.ggW8hZ1EuVLuxNuuIJKX_V8a_OMXzR0EHR9R6jgdqrOOF4daGU96Sr_P6q
    Jp6IcmD3HP99Obi1PRs-cwh3LO-p146waJ8IhehcwL7F09JdijmBqkvPeB2T9CJ
    NqeGpe-gccMg4vfKjkM8FcGvnzZUN4_KSP0aAp1tOJ1zZwgjxqGByKHiOtX7Tpd
    QyHE5lcMiKPXfEIQILVq0pc_E2DzL7emopWoaoZTF_m0_N0YzFC6g6EJbOEoRoS
    K5hoDalrcvRYLSrQAZZKflyuVCyixEoV9GfNQC3_osjzw2PAithfubEEBLuVVk4
    XUVrWOLrLl0nx7RkKU8NXNHq-rvKMzqg"
 
```

Claims:

* sub	
* name
* given_name
* family_name
* middle_name
* nickname
* preferred_username
* profile
* picture
* website
* email
* email_verified
* gender
* birthdate
* zoneinfo
* locale
* phone_number
* phone_number_verified
* address
* updated_at



### User Info endpoint

```
GET /userinfo HTTP/1.1
  Host: server.example.com
  Authorization: Bearer SlAV32hkKG

HTTP/1.1 200 OK
  Content-Type: application/json

{
  "sub": "248289761001",
  "name": "Jane Doe",
  "given_name": "Jane",
  "family_name": "Doe",
  "preferred_username": "j.doe",
  "email": "janedoe@example.com",
  "picture": "http://example.com/janedoe/me.jpg"
}

```


### OpenID Connect discovery [https://openid.net/specs/openid-connect-discovery-1_0.html]

OpenID Connect 1.0 is a simple identity layer on top of the OAuth 2.0 protocol.
It enables Clients to verify the identity of the End-User based on the
authentication performed by an Authorization Server, as well as to obtain basic
profile information about the End-User in an interoperable and REST-like manner.

Example: [https://aidbox.auth0.com/.well-known/openid-configuration]

* issuer
* authorization_endpoint
* token_endpoint
* userinfo_endpoint
* jwks_uri
* registration_endpoint
* scopes_supported
* response_types_supported
* response_modes_supported
* grant_types_supported
* acr_values_supported
* subject_types_supported
* id_token_signing_alg_values_supported
* id_token_encryption_alg_values_supported
...



### Dynamic client registration [https://openid.net/specs/openid-connect-registration-1_0.html]


```
POST /connect/register HTTP/1.1
Content-Type: application/json
Accept: application/json
Host: server.example.com
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJ ...

{
  "application_type": "web",
  "redirect_uris":
    ["https://client.example.org/callback",
    "https://client.example.org/callback2"],
  "client_name": "My Example",
  "client_name#ja-Jpan-JP":
    "クライアント名",
  "logo_uri": "https://client.example.org/logo.png",
  "subject_type": "pairwise",
  "sector_identifier_uri":
    "https://other.example.net/file_of_redirect_uris.json",
  "token_endpoint_auth_method": "client_secret_basic",
  "jwks_uri": "https://client.example.org/my_public_keys.jwks",
  "userinfo_encrypted_response_alg": "RSA1_5",
  "userinfo_encrypted_response_enc": "A128CBC-HS256",
  "contacts": ["ve7jtb@example.org", "mary@example.org"],
  "request_uris":
    ["https://client.example.org/rf.txt
      #qpXaRLh_n93TTR9F252ValdatUQvQiJi5BDub2BeznA"]
}

HTTP/1.1 201 Created
Content-Type: application/json
Cache-Control: no-store
Pragma: no-cache

{
  "client_id": "s6BhdRkqt3",
  "client_secret":
    "ZJYCqe3GGRvdrudKyZS0XhGv_Z45DuKhCUk0gBR1vZk",
  "client_secret_expires_at": 1577858400,
  "registration_access_token":
    "this.is.an.access.token.value.ffx83",
  "registration_client_uri":
    "https://server.example.com/connect/register?client_id=s6BhdRkqt3",
  "token_endpoint_auth_method":
    "client_secret_basic",
  "application_type": "web",
  "redirect_uris":
    ["https://client.example.org/callback",
    "https://client.example.org/callback2"],
  "client_name": "My Example",
  "client_name#ja-Jpan-JP":
    "クライアント名",
  "logo_uri": "https://client.example.org/logo.png",
  "subject_type": "pairwise",
  "sector_identifier_uri":
    "https://other.example.net/file_of_redirect_uris.json",
  "jwks_uri": "https://client.example.org/my_public_keys.jwks",
  "userinfo_encrypted_response_alg": "RSA1_5",
  "userinfo_encrypted_response_enc": "A128CBC-HS256",
  "contacts": ["ve7jtb@example.org", "mary@example.org"],
  "request_uris":
    ["https://client.example.org/rf.txt
      #qpXaRLh_n93TTR9F252ValdatUQvQiJi5BDub2BeznA"]
}
```


## OpenID Connect Federation [https://openid.net/specs/openid-connect-federation-1_0.html]

Metadata model + JWT sets

The trust model is based on linking together signing keys, referred to in the
metadata statements and represented asJWK Sets [RFC7517]. Each signature chain
is rooted in the trusted third party's signing keys. By verifying such signature
chains, the entities can establish trust in the metadata.
