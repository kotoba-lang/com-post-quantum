#!/usr/bin/env bash
# post_quantum_compat — clj/bb test suite (ADR-2606160842 py->clj port wave). Auto-wired into the fleet
# green-check; runs all cljc test namespaces via babashka from the repo root.
set -euo pipefail
cd "$(dirname "$0")"
exec bb -e '(doseq [f ["methods/suite.cljc" "methods/datom_emit.cljc" "methods/test_datom_emit.cljc" "methods/test_suite.cljc" "methods/test_suite_registry.cljc"]] (load-file f)) (require (quote clojure.test)) (let [r (apply clojure.test/run-tests (quote [post-quantum-compat.methods.test-datom-emit post-quantum-compat.methods.test-suite post-quantum-compat.methods.test-suite-registry]))] (System/exit (if (zero? (+ (:fail r) (:error r))) 0 1)))'
