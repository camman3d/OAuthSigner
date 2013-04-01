package com.joshmonson.oauth.test

/**
 * Runs the test cases.
 * TODO: Set it SBT tests
 */
object SignatureTester {

  def main(args: Array[String]) {

    var passed = 0
    for ((name, key, request, signature) <- TestCases.all) {
      println("\n-------------------------------")
      println("Testing: " + name)
      val generatedSignature = request.getSignature(key)
      if (signature == generatedSignature) {
        println("  PASSED!")
        passed += 1
      } else
        println("  FAILED! Expected: " + signature + " Actual: " + generatedSignature)
    }
    println("\n-------------------------------")
    println("Summary: " + passed + " Passed, " + (TestCases.all.size - passed) + " Failed.")


  }
}
