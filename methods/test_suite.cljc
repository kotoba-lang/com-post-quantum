#!/usr/bin/env bb
;; post-quantum-compat — first test suite for the quantum-cryptography risk model.
;; Run:  bb --classpath 20-actors 20-actors/post_quantum-compat/methods/test_suite.cljc
(ns post-quantum-compat.methods.test-suite
  "First tests for post-quantum-compat (suite.cljc had NONE). Pins the three quantum-risk
  primitives that decide which crypto layers are post-quantum-safe and when to migrate:
    grover-effective-bits — Grover's quadratic search halves a symmetric key's strength (BBBV bound)
    mosca                 — Mosca's inequality: migrate now iff shelf-life + migration > time-to-CRQC
    shor-applies          — Shor breaks a layer iff its quantum-attack is :shor (asymmetric crypto)
  A regression here would silently mis-rate the org's quantum exposure."
  (:require [post-quantum-compat.methods.suite :as s]
            [clojure.test :refer [deftest is run-tests]]))

(deftest grover-halves-symmetric-key-strength
  ;; Grover searches an n-bit key in 2^(n/2) → effective strength n/2 bits
  (is (= 128 (s/grover-effective-bits 256)) "AES-256 → 128-bit post-quantum strength")
  (is (= 96  (s/grover-effective-bits 192)))
  (is (= 64  (s/grover-effective-bits 128)) "AES-128 → only 64-bit under Grover")
  (is (= 127 (s/grover-effective-bits 255)) "odd key size floors")
  ;; the security consequence the model encodes: AES-256 stays ≥128 (safe), AES-128 drops below
  (is (>= (s/grover-effective-bits 256) 128) "AES-256 retains ≥128-bit security post-quantum")
  (is (<  (s/grover-effective-bits 128) 128) "AES-128 falls below the 128-bit floor under Grover"))

(deftest mosca-inequality-decides-migrate-now
  (let [act (s/mosca 10 15 20)]   ;; shelf 10 + migrate 15 = 25 > 20 (time-to-CRQC) → act now
    (is (true? (get act ":mosca/act-now")) "x+y > z → migrate now")
    (is (= -5 (get act ":mosca/slack-years")) "slack = z − (x+y) = −5"))
  (let [safe (s/mosca 10 5 20)]   ;; 15 < 20 → still safe
    (is (false? (get safe ":mosca/act-now")) "x+y < z → not yet")
    (is (= 5 (get safe ":mosca/slack-years"))))
  (let [edge (s/mosca 10 10 20)]  ;; exactly 20 → slack 0, NOT act-now (strict inequality)
    (is (false? (get edge ":mosca/act-now")) "x+y = z is the boundary: not act-now (just enough time)")
    (is (= 0 (get edge ":mosca/slack-years")))))

(deftest shor-applies-only-to-asymmetric-layers
  (is (true?  (s/shor-applies {":layer/quantum-attack" ":shor"}))
      "Shor breaks an asymmetric (:shor) layer — RSA/ECC")
  (is (false? (s/shor-applies {":layer/quantum-attack" ":grover"}))
      "Shor does not apply to a symmetric (:grover) layer")
  (is (false? (s/shor-applies {}))
      "a layer with no quantum-attack tag is not Shor-breakable"))

#?(:clj
   (when (= *file* (System/getProperty "babashka.file"))
     (let [{:keys [fail error]} (run-tests 'post-quantum-compat.methods.test-suite)]
       (System/exit (if (zero? (+ fail error)) 0 1)))))
