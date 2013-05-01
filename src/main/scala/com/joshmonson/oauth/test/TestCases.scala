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
  val get = List[(String, OAuthKey, OAuthRequest, String, Boolean)](
    (
      "OAuth Spec example",
      OAuthKey("dpf43f3p2l4k3l03", "kd94hf93k423kf44", "nnch734d00sl2jdk", "pfkkdhi9sl3r4s00"),
      OAuthRequest(None, None, "http://photos.example.net", "file=vacation.jpg&oauth_consumer_key=dpf43f3p2l4k3l03&oauth_nonce=kllo9940pd9333jh&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1191242096&oauth_token=nnch734d00sl2jdk&oauth_version=1.0&size=original", "", "GET", "/photos"),
      "tR3+Ty81lMeYAr/Fid0kMTYa/WM=",
      false
      ),

    (
      "(1a 2a 3a 4a 5a) GET w/ query string, OAuth info in query string, & token",
      OAuthKey("dpf43f3p2l4k3l03", "kd94hf93k423kf44", "nnch734d00sl2jdk", "pfkkdhi9sl3r4s00"),
      OAuthRequest(None, None, "http://www.example.com", "one=two&three=4&five=true&oauth_version=1.0&oauth_consumer_key=dpf43f3p2l4k3l03&oauth_token=nnch734d00sl2jdk&oauth_timestamp=1364831304&oauth_nonce=XHrKehfTwtz&oauth_signature_method=HMAC-SHA1", "", "GET", "/a/b/c"),
      "1XVcmw43GZCfDdVzFntWWjQOZco=",
      false
      ),

    (
      "(1a 2a 3a 4a 5b) GET w/ query string, OAuth info in query string, & no token",
      OAuthKey("dpf43f3p2l4k3l03", "kd94hf93k423kf44", "", ""),
      OAuthRequest(None, None, "http://www.example.com", "one=two&three=4&five=true&oauth_version=1.0&oauth_consumer_key=dpf43f3p2l4k3l03&oauth_timestamp=1364831304&oauth_nonce=XHrKehfTwtz&oauth_signature_method=HMAC-SHA1", "", "GET", "/a/b/c"),
      "mkwGZwyhm8r95Nl9u3MzVSChWFc=",
      false
      ),

    (
      "(1a 2a 3a 4c 5a) GET w/ query string, OAuth info in auth header, & token",
      OAuthKey("dpf43f3p2l4k3l03", "kd94hf93k423kf44", "nnch734d00sl2jdk", "pfkkdhi9sl3r4s00"),
      OAuthRequest(Some("OAuth realm=\"\",oauth_version=\"1.0\",oauth_consumer_key=\"dpf43f3p2l4k3l03\",oauth_token=\"nnch734d00sl2jdk\",oauth_timestamp=\"1364832782\",oauth_nonce=\"05BIxgmqUdG\",oauth_signature_method=\"HMAC-SHA1\",oauth_signature=\"T%2FDd5u6efds4QoXv4%2B5a4LgNuw8%3D\""),
        None, "http://www.example.com/", "one=two&three=4&five=true", "", "GET", "/a/b/c"),
      "T/Dd5u6efds4QoXv4+5a4LgNuw8=",
      true
      ),

    (
      "(1a 2a 3a 4c 5b) GET w/ query string, OAuth info in auth header, & no token",
      OAuthKey("dpf43f3p2l4k3l03", "kd94hf93k423kf44", "", ""),
      OAuthRequest(Some("OAuth realm=\"\",oauth_version=\"1.0\",oauth_consumer_key=\"dpf43f3p2l4k3l03\",oauth_timestamp=\"1364832859\",oauth_nonce=\"t6I0e1iOVR9\",oauth_signature_method=\"HMAC-SHA1\",oauth_signature=\"NjPOAstQW1jtIUKx%2BNbyWqj49Tw%3D\""),
        None, "http://www.example.com/", "one=two&three=4&five=true", "", "GET", "/a/b/c"),
      "NjPOAstQW1jtIUKx+NbyWqj49Tw=",
      true
      ),

    (
      "(1a 2b 3a 4c 5a) GET w/out query string, OAuth info in auth header, & token",
      OAuthKey("dpf43f3p2l4k3l03", "kd94hf93k423kf44", "nnch734d00sl2jdk", "pfkkdhi9sl3r4s00"),
      OAuthRequest(Some("OAuth realm=\"\",oauth_version=\"1.0\",oauth_consumer_key=\"dpf43f3p2l4k3l03\",oauth_token=\"nnch734d00sl2jdk\",oauth_timestamp=\"1364832782\",oauth_nonce=\"05BIxgmqUdG\",oauth_signature_method=\"HMAC-SHA1\",oauth_signature=\"G1bjkhHnev1wqUtgJ4h3KwUX%2BJc%3D\""),
        None, "http://www.example.com/", "", "", "GET", "/a/b/c"),
      "G1bjkhHnev1wqUtgJ4h3KwUX+Jc=",
      true
      ),

    (
      "(1a 2b 3a 4c 5b) GET w/out query string, OAuth info in auth header, & no token",
      OAuthKey("dpf43f3p2l4k3l03", "kd94hf93k423kf44", "", ""),
      OAuthRequest(Some("OAuth realm=\"\",oauth_version=\"1.0\",oauth_consumer_key=\"dpf43f3p2l4k3l03\",oauth_timestamp=\"1364832782\",oauth_nonce=\"05BIxgmqUdG\",oauth_signature_method=\"HMAC-SHA1\",oauth_signature=\"AGe8ZI9RWjzqj7m7otFWrZuVdh8%3D\""),
        None, "http://www.example.com/", "", "", "GET", "/a/b/c"),
      "AGe8ZI9RWjzqj7m7otFWrZuVdh8=",
      true
      ),

    (
      "Empty parameter",
      OAuthKey("dpf43f3p2l4k3l03", "kd94hf93k423kf44", "nnch734d00sl2jdk", "pfkkdhi9sl3r4s00"),
      OAuthRequest(None, None, "http://photos.example.net", "file=&oauth_consumer_key=dpf43f3p2l4k3l03&oauth_nonce=kllo9940pd9333jh&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1191242096&oauth_token=nnch734d00sl2jdk&oauth_version=1.0", "", "GET", "/photos"),
      "nA8DOmbK7aNhJJEE6zAhaBHfPls=",
      false
      )



  )

  // POST test cases
  val post = List[(String, OAuthKey, OAuthRequest, String, Boolean)](
    (
      "(1b 2a 3a 4a 5a) POST w/ query string, OAuth info in query string, & token",
      OAuthKey("dpf43f3p2l4k3l03", "kd94hf93k423kf44", "nnch734d00sl2jdk", "pfkkdhi9sl3r4s00"),
      OAuthRequest(None, None, "http://www.example.com", "one=two&three=4&five=true&oauth_version=1.0&oauth_consumer_key=dpf43f3p2l4k3l03&oauth_token=nnch734d00sl2jdk&oauth_timestamp=1364831304&oauth_nonce=XHrKehfTwtz&oauth_signature_method=HMAC-SHA1", "", "POST", "/a/b/c"),
      "9N+WHPkWFz8R5EmgLVNZHQ/k3fM=",
      false
      ),

    (
      "(1b 2a 3a 4a 5b) POST w/ query string, OAuth info in query string, & no token",
      OAuthKey("dpf43f3p2l4k3l03", "kd94hf93k423kf44", "", ""),
      OAuthRequest(None, None, "http://www.example.com", "one=two&three=4&five=true&oauth_version=1.0&oauth_consumer_key=dpf43f3p2l4k3l03&oauth_timestamp=1364831304&oauth_nonce=XHrKehfTwtz&oauth_signature_method=HMAC-SHA1", "", "POST", "/a/b/c"),
      "cruNRrAjanx/gA79NLHqCnVq93I=",
      false
      ),

    (
      "(1b 2a 3a 4b 5a) POST w/ query string, OAuth info in body, & token",
      OAuthKey("dpf43f3p2l4k3l03", "kd94hf93k423kf44", "nnch734d00sl2jdk", "pfkkdhi9sl3r4s00"),
      OAuthRequest(None, Some(OAuthValues.urlEncodedContentType), "http://www.example.com", "one=two&three=4&five=true", "oauth_version=1.0&oauth_consumer_key=dpf43f3p2l4k3l03&oauth_timestamp=1364831304&oauth_token=nnch734d00sl2jdk&oauth_nonce=XHrKehfTwtz&oauth_signature_method=HMAC-SHA1", "POST", "/a/b/c"),
      "9N+WHPkWFz8R5EmgLVNZHQ/k3fM=",
      false
      ),

    (
      "(1b 2a 3a 4b 5b) POST w/ query string, OAuth info in body, & no token",
      OAuthKey("dpf43f3p2l4k3l03", "kd94hf93k423kf44", "", ""),
      OAuthRequest(None, Some(OAuthValues.urlEncodedContentType), "http://www.example.com", "one=two&three=4&five=true", "oauth_version=1.0&oauth_consumer_key=dpf43f3p2l4k3l03&oauth_timestamp=1364831304&oauth_nonce=XHrKehfTwtz&oauth_signature_method=HMAC-SHA1", "POST", "/a/b/c"),
      "cruNRrAjanx/gA79NLHqCnVq93I=",
      false
      ),

    (
      "(1b 2b 3b 4c 5a) POST w/out query string, url encoded body, OAuth info in header, & token",
      OAuthKey("dpf43f3p2l4k3l03", "kd94hf93k423kf44", "nnch734d00sl2jdk", "pfkkdhi9sl3r4s00"),
      OAuthRequest(Some("OAuth realm=\"\",oauth_version=\"1.0\",oauth_consumer_key=\"dpf43f3p2l4k3l03\",oauth_token=\"nnch734d00sl2jdk\",oauth_timestamp=\"1364831304\",oauth_nonce=\"XHrKehfTwtz\",oauth_signature_method=\"HMAC-SHA1\",oauth_signature=\"9N%2BWHPkWFz8R5EmgLVNZHQ%2Fk3fM%3D\""),
        Some(OAuthValues.urlEncodedContentType), "http://www.example.com", "", "one=two&three=4&five=true", "POST", "/a/b/c"),
      "9N+WHPkWFz8R5EmgLVNZHQ/k3fM=",
      true
      ),

    (
      "(1b 2b 3b 4c 5b) POST w/out query string, url encoded body, OAuth info in header, & no token",
      OAuthKey("dpf43f3p2l4k3l03", "kd94hf93k423kf44", "", ""),
      OAuthRequest(Some("OAuth realm=\"\",oauth_version=\"1.0\",oauth_consumer_key=\"dpf43f3p2l4k3l03\",oauth_timestamp=\"1364831304\",oauth_nonce=\"XHrKehfTwtz\",oauth_signature_method=\"HMAC-SHA1\",oauth_signature=\"cruNRrAjanx%2FgA79NLHqCnVq93I%3D\""),
        Some(OAuthValues.urlEncodedContentType), "http://www.example.com", "", "one=two&three=4&five=true", "POST", "/a/b/c"),
      "cruNRrAjanx/gA79NLHqCnVq93I=",
      true
      ),

    (
      "Moodle test 1",
      OAuthKey("7", "886310c459786a2d31e83599b9b59cb6", "", ""),
      OAuthRequest(None, Some("application/x-www-form-urlencoded"), "localhost:9000", "",
        "oauth_version=1.0&oauth_nonce=07c2c197f73092dc920c8f99785ac31e&oauth_timestamp=1367449105&oauth_consumer_key=7&resource_link_id=16&resource_link_title=Ayamel&resource_link_description=&user_id=2&roles=Instructor%2Curn%3Alti%3Asysrole%3Aims%2Flis%2FAdministrator&context_id=4&context_label=Ayamel&context_title=Ayamel&launch_presentation_locale=en&lis_result_sourcedid=%7B%22data%22%3A%7B%22instanceid%22%3A%2216%22%2C%22userid%22%3A%222%22%2C%22launchid%22%3A104165179%7D%2C%22hash%22%3A%2215ad38a0995d2ef4701de278151dbecb8306948bc8d26232e2c73ae1119d2a10%22%7D&lis_outcome_service_url=http%3A%2F%2Flocalhost%2Fmoodle%2Fmod%2Flti%2Fservice.php&lis_person_name_given=Admin&lis_person_name_family=User&lis_person_name_full=Admin+User&lis_person_contact_email_primary=camman3d%40gmail.com&ext_lms=moodle-2&tool_consumer_info_product_family_code=moodle&tool_consumer_info_version=2011120503.06&oauth_callback=about%3Ablank&lti_version=LTI-1p0&lti_message_type=basic-lti-launch-request&tool_consumer_instance_guid=localhost&oauth_signature_method=HMAC-SHA1&oauth_signature=%2BGtHIcTb2Yy2tmGRQfIj%2BawDwRk%3D&ext_submit=Press+to+launch+this+activity",
        "POST",
        "/course/7/ltiAuth"),
      "+GtHIcTb2Yy2tmGRQfIj+awDwRk=",
      true
      )
  )

  // oauth_body_hash tests
  val bodyHash = List[(String, OAuthKey, OAuthRequest, String, Boolean)](
    (
      "(1b 2b 3b 4c 5a) POST w/out query string, other content type, OAuth info in header, & token",
      OAuthKey("dpf43f3p2l4k3l03", "kd94hf93k423kf44", "nnch734d00sl2jdk", "pfkkdhi9sl3r4s00"),
      OAuthRequest(Some("OAuth realm=\"\",oauth_body_hash=\"Lve95gjOVATpfV8EL5X4nxwjKHE%3D\",oauth_version=\"1.0\",oauth_consumer_key=\"dpf43f3p2l4k3l03\",oauth_token=\"nnch734d00sl2jdk\",oauth_timestamp=\"1364831304\",oauth_nonce=\"XHrKehfTwtz\",oauth_signature_method=\"HMAC-SHA1\",oauth_signature=\"u4vdSdXBcM7oK3GF9GalZruegl8%3D\""),
        Some("text/plain"), "www.example.com", "", "Hello World!", "POST", "/resource"),
      "u4vdSdXBcM7oK3GF9GalZruegl8=",
      true
      ),

    (
      "(1b 2b 3b 4c 5b) POST w/out query string, other content type, OAuth info in header, & no token",
      OAuthKey("dpf43f3p2l4k3l03", "kd94hf93k423kf44", "", ""),
      OAuthRequest(Some("OAuth realm=\"\",oauth_body_hash=\"Lve95gjOVATpfV8EL5X4nxwjKHE%3D\",oauth_version=\"1.0\",oauth_consumer_key=\"dpf43f3p2l4k3l03\",oauth_timestamp=\"1364831304\",oauth_nonce=\"XHrKehfTwtz\",oauth_signature_method=\"HMAC-SHA1\",oauth_signature=\"2ZEqSnKlFAy1Uqq6oS2o25HHF%2FQ%3D\""),
        Some("text/plain"), "www.example.com", "", "Hello World!", "POST", "/resource"),
      "2ZEqSnKlFAy1Uqq6oS2o25HHF/Q=",
      true
      )
  )

  def all: List[(String, OAuthKey, OAuthRequest, String, Boolean)] = get ::: post ::: bodyHash

}
