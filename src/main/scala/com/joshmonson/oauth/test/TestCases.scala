package com.joshmonson.oauth.test

import com.joshmonson.oauth.{OAuthValues, OAuthRequest, OAuthKey}

object TestCases {

  /*
   * There are five dimensions to the test cases:
   * 1. Method
   *   a. GET (no body)
   *   b. POST (body)
   * 2. Query string
   *   a. Yes
   *   b. No
   * 3. Data (for POST only)
   *   a. None
   *   b. URL encoded
   *   c. Other content type
   * 4. OAuth info
   *   a. Query string
   *   b. URL encoded body
   *   c. Authorization header
   * 5. Token
   *   a. Yes
   *   b. No
   */

  // GET test cases
  val get = List[(String, OAuthKey, OAuthRequest, String)](
    (
      "OAuth Spec example",
      OAuthKey("dpf43f3p2l4k3l03", "kd94hf93k423kf44", "nnch734d00sl2jdk", "pfkkdhi9sl3r4s00"),
      OAuthRequest(None, None, "http://photos.example.net", "file=vacation.jpg&oauth_consumer_key=dpf43f3p2l4k3l03&oauth_nonce=kllo9940pd9333jh&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1191242096&oauth_token=nnch734d00sl2jdk&oauth_version=1.0&size=original", "", "GET", "/photos"),
      "tR3+Ty81lMeYAr/Fid0kMTYa/WM="
      ),

    (
      "(1a 2a 3a 4a 5a) GET w/ query string, OAuth info in query string, & token",
      OAuthKey("dpf43f3p2l4k3l03", "kd94hf93k423kf44", "nnch734d00sl2jdk", "pfkkdhi9sl3r4s00"),
      OAuthRequest(None, None, "http://www.example.com", "one=two&three=4&five=true&oauth_version=1.0&oauth_consumer_key=dpf43f3p2l4k3l03&oauth_token=nnch734d00sl2jdk&oauth_timestamp=1364831304&oauth_nonce=XHrKehfTwtz&oauth_signature_method=HMAC-SHA1", "", "GET", "/a/b/c"),
      "1XVcmw43GZCfDdVzFntWWjQOZco="
      ),

    (
      "(1a 2a 3a 4a 5b) GET w/ query string, OAuth info in query string, & no token",
      OAuthKey("dpf43f3p2l4k3l03", "kd94hf93k423kf44", "", ""),
      OAuthRequest(None, None, "http://www.example.com", "one=two&three=4&five=true&oauth_version=1.0&oauth_consumer_key=dpf43f3p2l4k3l03&oauth_timestamp=1364831304&oauth_nonce=XHrKehfTwtz&oauth_signature_method=HMAC-SHA1", "", "GET", "/a/b/c"),
      "mkwGZwyhm8r95Nl9u3MzVSChWFc="
      ),

    (
      "(1a 2a 3a 4c 5a) GET w/ query string, OAuth info in auth header, & token",
      OAuthKey("dpf43f3p2l4k3l03", "kd94hf93k423kf44", "nnch734d00sl2jdk", "pfkkdhi9sl3r4s00"),
      OAuthRequest(Some("OAuth realm=\"\",oauth_version=\"1.0\",oauth_consumer_key=\"dpf43f3p2l4k3l03\",oauth_token=\"nnch734d00sl2jdk\",oauth_timestamp=\"1364832782\",oauth_nonce=\"05BIxgmqUdG\",oauth_signature_method=\"HMAC-SHA1\",oauth_signature=\"T%2FDd5u6efds4QoXv4%2B5a4LgNuw8%3D\""),
        None, "http://www.example.com/", "one=two&three=4&five=true", "", "GET", "/a/b/c"),
      "T/Dd5u6efds4QoXv4+5a4LgNuw8="
      ),

    (
      "(1a 2a 3a 4c 5b) GET w/ query string, OAuth info in auth header, & no token",
      OAuthKey("dpf43f3p2l4k3l03", "kd94hf93k423kf44", "", ""),
      OAuthRequest(Some("OAuth realm=\"\",oauth_version=\"1.0\",oauth_consumer_key=\"dpf43f3p2l4k3l03\",oauth_timestamp=\"1364832859\",oauth_nonce=\"t6I0e1iOVR9\",oauth_signature_method=\"HMAC-SHA1\",oauth_signature=\"NjPOAstQW1jtIUKx%2BNbyWqj49Tw%3D\""),
        None, "http://www.example.com/", "one=two&three=4&five=true", "", "GET", "/a/b/c"),
      "NjPOAstQW1jtIUKx+NbyWqj49Tw="
      ),

    (
      "(1a 2b 3a 4c 5a) GET w/out query string, OAuth info in auth header, & token",
      OAuthKey("dpf43f3p2l4k3l03", "kd94hf93k423kf44", "nnch734d00sl2jdk", "pfkkdhi9sl3r4s00"),
      OAuthRequest(Some("OAuth realm=\"\",oauth_version=\"1.0\",oauth_consumer_key=\"dpf43f3p2l4k3l03\",oauth_token=\"nnch734d00sl2jdk\",oauth_timestamp=\"1364832782\",oauth_nonce=\"05BIxgmqUdG\",oauth_signature_method=\"HMAC-SHA1\",oauth_signature=\"G1bjkhHnev1wqUtgJ4h3KwUX%2BJc%3D\""),
        None, "http://www.example.com/", "", "", "GET", "/a/b/c"),
      "G1bjkhHnev1wqUtgJ4h3KwUX+Jc="
      ),

    (
      "(1a 2b 3a 4c 5b) GET w/out query string, OAuth info in auth header, & no token",
      OAuthKey("dpf43f3p2l4k3l03", "kd94hf93k423kf44", "", ""),
      OAuthRequest(Some("OAuth realm=\"\",oauth_version=\"1.0\",oauth_consumer_key=\"dpf43f3p2l4k3l03\",oauth_timestamp=\"1364832782\",oauth_nonce=\"05BIxgmqUdG\",oauth_signature_method=\"HMAC-SHA1\",oauth_signature=\"AGe8ZI9RWjzqj7m7otFWrZuVdh8%3D\""),
        None, "http://www.example.com/", "", "", "GET", "/a/b/c"),
      "AGe8ZI9RWjzqj7m7otFWrZuVdh8="
      ),

    (
      "Empty parameter",
      OAuthKey("dpf43f3p2l4k3l03", "kd94hf93k423kf44", "nnch734d00sl2jdk", "pfkkdhi9sl3r4s00"),
      OAuthRequest(None, None, "http://photos.example.net", "file=&oauth_consumer_key=dpf43f3p2l4k3l03&oauth_nonce=kllo9940pd9333jh&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1191242096&oauth_token=nnch734d00sl2jdk&oauth_version=1.0", "", "GET", "/photos"),
      "nA8DOmbK7aNhJJEE6zAhaBHfPls="
      )

  )

  // POST test cases
  val post = List[(String, OAuthKey, OAuthRequest, String)](
    (
      "(1b 2a 3a 4a 5a) POST w/ query string, OAuth info in query string, & token",
      OAuthKey("dpf43f3p2l4k3l03", "kd94hf93k423kf44", "nnch734d00sl2jdk", "pfkkdhi9sl3r4s00"),
      OAuthRequest(None, None, "http://www.example.com", "one=two&three=4&five=true&oauth_version=1.0&oauth_consumer_key=dpf43f3p2l4k3l03&oauth_token=nnch734d00sl2jdk&oauth_timestamp=1364831304&oauth_nonce=XHrKehfTwtz&oauth_signature_method=HMAC-SHA1", "", "POST", "/a/b/c"),
      "9N+WHPkWFz8R5EmgLVNZHQ/k3fM="
      ),

    (
      "(1b 2a 3a 4a 5b) POST w/ query string, OAuth info in query string, & no token",
      OAuthKey("dpf43f3p2l4k3l03", "kd94hf93k423kf44", "", ""),
      OAuthRequest(None, None, "http://www.example.com", "one=two&three=4&five=true&oauth_version=1.0&oauth_consumer_key=dpf43f3p2l4k3l03&oauth_timestamp=1364831304&oauth_nonce=XHrKehfTwtz&oauth_signature_method=HMAC-SHA1", "", "POST", "/a/b/c"),
      "cruNRrAjanx/gA79NLHqCnVq93I="
      ),

    (
      "(1b 2a 3a 4b 5a) POST w/ query string, OAuth info in body, & token",
      OAuthKey("dpf43f3p2l4k3l03", "kd94hf93k423kf44", "nnch734d00sl2jdk", "pfkkdhi9sl3r4s00"),
      OAuthRequest(None, Some(OAuthValues.urlEncodedContentType), "http://www.example.com", "one=two&three=4&five=true", "oauth_version=1.0&oauth_consumer_key=dpf43f3p2l4k3l03&oauth_timestamp=1364831304&oauth_token=nnch734d00sl2jdk&oauth_nonce=XHrKehfTwtz&oauth_signature_method=HMAC-SHA1", "POST", "/a/b/c"),
      "9N+WHPkWFz8R5EmgLVNZHQ/k3fM="
      ),

    (
      "(1b 2a 3a 4b 5b) POST w/ query string, OAuth info in body, & no token",
      OAuthKey("dpf43f3p2l4k3l03", "kd94hf93k423kf44", "", ""),
      OAuthRequest(None, Some(OAuthValues.urlEncodedContentType), "http://www.example.com", "one=two&three=4&five=true", "oauth_version=1.0&oauth_consumer_key=dpf43f3p2l4k3l03&oauth_timestamp=1364831304&oauth_nonce=XHrKehfTwtz&oauth_signature_method=HMAC-SHA1", "POST", "/a/b/c"),
      "cruNRrAjanx/gA79NLHqCnVq93I="
      ),

    (
      "(1b 2b 3b 4c 5a) POST w/out query string, url encoded body, OAuth info in header, & token",
      OAuthKey("dpf43f3p2l4k3l03", "kd94hf93k423kf44", "nnch734d00sl2jdk", "pfkkdhi9sl3r4s00"),
      OAuthRequest(Some("OAuth realm=\"\",oauth_version=\"1.0\",oauth_consumer_key=\"dpf43f3p2l4k3l03\",oauth_token=\"nnch734d00sl2jdk\",oauth_timestamp=\"1364831304\",oauth_nonce=\"XHrKehfTwtz\",oauth_signature_method=\"HMAC-SHA1\",oauth_signature=\"9N%2BWHPkWFz8R5EmgLVNZHQ%2Fk3fM%3D\""),
        Some(OAuthValues.urlEncodedContentType), "http://www.example.com", "", "one=two&three=4&five=true", "POST", "/a/b/c"),
      "9N+WHPkWFz8R5EmgLVNZHQ/k3fM="
      ),

    (
      "(1b 2b 3b 4c 5b) POST w/out query string, url encoded body, OAuth info in header, & no token",
      OAuthKey("dpf43f3p2l4k3l03", "kd94hf93k423kf44", "", ""),
      OAuthRequest(Some("OAuth realm=\"\",oauth_version=\"1.0\",oauth_consumer_key=\"dpf43f3p2l4k3l03\",oauth_timestamp=\"1364831304\",oauth_nonce=\"XHrKehfTwtz\",oauth_signature_method=\"HMAC-SHA1\",oauth_signature=\"cruNRrAjanx%2FgA79NLHqCnVq93I%3D\""),
        Some(OAuthValues.urlEncodedContentType), "http://www.example.com", "", "one=two&three=4&five=true", "POST", "/a/b/c"),
      "cruNRrAjanx/gA79NLHqCnVq93I="
      )
  )

  // oauth_body_hash tests
  val bodyHash = List[(String, OAuthKey, OAuthRequest, String)](
    (
      "(1b 2b 3b 4c 5a) POST w/out query string, other content type, OAuth info in header, & token",
      OAuthKey("dpf43f3p2l4k3l03", "kd94hf93k423kf44", "nnch734d00sl2jdk", "pfkkdhi9sl3r4s00"),
      OAuthRequest(Some("OAuth realm=\"\",oauth_body_hash=\"Lve95gjOVATpfV8EL5X4nxwjKHE%3D\",oauth_version=\"1.0\",oauth_consumer_key=\"dpf43f3p2l4k3l03\",oauth_token=\"nnch734d00sl2jdk\",oauth_timestamp=\"1364831304\",oauth_nonce=\"XHrKehfTwtz\",oauth_signature_method=\"HMAC-SHA1\",oauth_signature=\"u4vdSdXBcM7oK3GF9GalZruegl8%3D\""),
        Some("text/plain"), "www.example.com", "", "Hello World!", "POST", "/resource"),
      "u4vdSdXBcM7oK3GF9GalZruegl8="
      ),

    (
      "(1b 2b 3b 4c 5b) POST w/out query string, other content type, OAuth info in header, & no token",
      OAuthKey("dpf43f3p2l4k3l03", "kd94hf93k423kf44", "", ""),
      OAuthRequest(Some("OAuth realm=\"\",oauth_body_hash=\"Lve95gjOVATpfV8EL5X4nxwjKHE%3D\",oauth_version=\"1.0\",oauth_consumer_key=\"dpf43f3p2l4k3l03\",oauth_timestamp=\"1364831304\",oauth_nonce=\"XHrKehfTwtz\",oauth_signature_method=\"HMAC-SHA1\",oauth_signature=\"iroNXEIj1W6y9oxG54ir6Pz3SaQ%3D\""),
        Some("text/plain"), "www.example.com", "", "Hello World!", "POST", "/resource"),
      "2ZEqSnKlFAy1Uqq6oS2o25HHF/Q="
      )
  )

  def all: List[(String, OAuthKey, OAuthRequest, String)] = get ::: post ::: bodyHash

}
