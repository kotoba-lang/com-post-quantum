#!/usr/bin/env bb
;; Clojure test for methods/suite.cljc + datom_emit.cljc — post_quantum-compat.
;; (No python test existed; this is fresh coverage. `emit` is byte-identical to
;;  the python emitter — verified by run_tests.sh's diff step.)
;;
;; NOTE: the actor dir `post_quantum-compat` contains a literal '-', which a
;; babashka classpath namespace cannot munge to, so we `load-file` the two source
;; files (*file*-relative) before the ns form — this registers the namespaces
;; in-memory so the requires below resolve to them. Run:  bb <this file>.
(def ^:private here (-> *file* java.io.File. .getAbsoluteFile .getParent))
(load-file (str here "/suite.cljc"))
(load-file (str here "/datom_emit.cljc"))

(ns post-quantum-compat.methods.test-suite
  "Guards the pqh-v1 migration registry coverage readout (11 layers / 7 shor /
  3 migrated / fraction 0.4286 — parity with suite.py), the Mosca + Grover math,
  and the datom_emit GROUND+DERIVED projection (per-layer datoms, suite-component
  datoms, transient coverage block)."
  (:require [post-quantum-compat.methods.suite :as s]
            [post-quantum-compat.methods.datom-emit :as de]
            [clojure.string :as str]
            [clojure.test :refer [deftest is run-tests]]))

(deftest coverage-report-parity
  (let [c (s/coverage-report)]
    (is (= 11 (get c ":coverage/layers-total")))
    (is (= 7  (get c ":coverage/shor-vulnerable")))
    (is (= 3  (get c ":coverage/migrated")))
    (is (= 4  (get c ":coverage/gated")))
    (is (= 0  (get c ":coverage/unknown")))
    (is (= 0.4286 (get c ":coverage/migrated-fraction")))
    (is (= [":layer/governance-signature" ":layer/libsignal-path"
            ":layer/passkey-signature" ":layer/production-pq-keys"]
           (get c ":coverage/gated-ids")))))

(deftest grover-quadratic-bound
  (is (= 128 (s/grover-effective-bits 256)))
  (is (= 64 (s/grover-effective-bits 128))))

(deftest mosca-inequality
  (is (= {":mosca/act-now" false ":mosca/slack-years" 3} (s/mosca 10 2 15)))
  ;; x+y > z ⇒ act now (negative slack)
  (is (true? (get (s/mosca 10 8 15) ":mosca/act-now"))))

(deftest shor-applies-only-to-asymmetric
  (is (s/shor-applies {":layer/quantum-attack" ":shor"}))
  (is (not (s/shor-applies {":layer/quantum-attack" ":grover"}))))

(deftest emit-ground-and-derived
  (let [out (de/emit 1)]
    ;; a known GROUND layer datom (key-wrap migrated to pqh-v1)
    (is (str/includes? out "[:layer/key-wrap :layer/status :migrated 1 :add]"))
    ;; :layer/pr vector rendered
    (is (str/includes? out "[:layer/key-wrap :layer/pr [1616 1621] 1 :add]"))
    ;; a suite-component datom (nested dict flattened onto the suite entity; plain
    ;; string value is quoted, keyword-string value stays unquoted)
    (is (str/includes? out "[:suite/pqh-v1 :kem/pq \"ML-KEM-768\" 1 :add]"))
    (is (str/includes? out "[:suite/pqh-v1 :kem/pq-public-bytes 1184 1 :add]"))
    ;; DERIVED transient coverage block
    (is (str/includes? out ";; ── DERIVED"))
    (is (str/includes? out "[:pq/coverage :coverage/migrated-fraction 0.4286 1 :add] ;; :pq/is-transient true"))))

(deftest emit-tx-parameter-threads-through
  (is (str/includes? (de/emit 7) "[:layer/key-wrap :layer/status :migrated 7 :add]")))

(when (= *file* (System/getProperty "babashka.file"))
  (let [{:keys [fail error]} (run-tests 'post-quantum-compat.methods.test-suite)]
    (System/exit (if (zero? (+ fail error)) 0 1))))
