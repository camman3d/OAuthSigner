# OAuth 1.0a Signer and Verifier
By Joshua Monson

## Summary
### Description
This is a simple library that is designed to do one thing well: OAuth 1.0a Request Signing. This includes the body hash extension for content types other than `application/x-www-form-urlencoded`.

### Motivation
After spending literally countless hours struggling with various OAuth library only to come to a realization that the authors either implemented the spec incorrectly or didn't implement the body hash extension, I finally broke in and wrote this library.

While I definitely have a preferred framework, this library was built web-framework agnostic so that is can be used in any without much difficulty.

## Usage

### Examples
To sign a request, create an OAuthRequest object and sign it with an OAuthKey object:
```scala
val key = OAuthKey("consumerKey", "consumerSecret", "tokenKey", "tokenSecret")
val request = OAuthRequest(None, None, "http://example.com", "one=two&three=4", "", "GET", "/resource")
val authHeader = request.getAuthorizationHeader(key)
```

You can also sign POST requests:
```scala
val key = OAuthKey("consumerKey", "consumerSecret", "tokenKey", "tokenSecret")
val request = OAuthRequest(None, Some("application/x-www-form-urlencoded"), "http://example.com", "", "username=billy", "POST", "/some/auth")
val authHeader = request.getAuthorizationHeader(key)
```

With the body hash extension, you can sign POST requests with other content types:
```scala
val key = OAuthKey("consumerKey", "consumerSecret", "tokenKey", "tokenSecret")
val request = OAuthRequest(None, Some("application/xml"), "http://example.com", "", "<parent><child></child></parent>", "POST", "/some/thing")
val authHeader = request.getAuthorizationHeader(key)
```

Given a request, you can verify that it is valid and correct given a key:
```scala
val key = OAuthKey("consumerKey", "consumerSecret", "tokenKey", "tokenSecret")
val authHeader = (get the Authorization header as a String)
val request = OAuthRequest(Some(authHeader), None, "http://example.com", "", "", "GET", "/another")
val valid = request.verify(key)
```

### Documentation
The scaladoc is available here:
http://joshmonson.com/oauthApi/#com.joshmonson.oauth.package