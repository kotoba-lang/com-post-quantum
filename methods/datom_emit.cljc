(ns post-quantum-compat.methods.datom-emit
  "post_quantum-compat — kotoba Datom-log emitter (1:1 Clojure port of
  methods/datom_emit.py, canonical EAVT state, ADR-2605312345). Projects the
  pqh-v1 migration registry into append-only kotoba Datoms [e a v tx op].

  GROUND (op :add) — one datom per (layer, attribute, value) + per suite
    component: the migration state IS the Datom log.
  DERIVED (:pq/is-transient) — the coverage readout computed on READ, in a
    flagged block so a reader never mistakes it for persisted state.

  Pure stdlib."
  (:require [clojure.string :as str]
            [post-quantum-compat.methods.suite :as s]))

(def ^:private layer-attrs
  [":layer/primitive" ":layer/quantum-attack" ":layer/status" ":layer/suite" ":layer/adr" ":layer/note"])

(defn- fmt
  "Render an EDN value (1:1 with datom_emit.py `_fmt`)."
  [v]
  (cond
    (true? v) "true"
    (false? v) "false"
    (nil? v) "nil"
    (string? v) (if (str/starts-with? v ":")
                  v
                  (str \" (-> v (str/replace "\\" "\\\\") (str/replace "\"" "\\\"")) \"))
    (float? v) (str v)                                   ; python f"{v:g}" — exact for 0.4286-class values
    (sequential? v) (str "[" (str/join " " (map fmt v)) "]")
    :else (str v)))

(defn emit
  "Render the full GROUND + DERIVED datom log as a string."
  ([] (emit 1))
  ([tx]
   (let [lines (transient
                [";; post_quantum-compat — GENERATED kotoba Datom log (ADR-2606111300). DO NOT hand-edit."
                 ";; Canonical EAVT state (ADR-2605312345). [e a v tx op]."
                 ";; GROUND op :add = durable. DERIVED :pq/is-transient = computed on read."
                 ""])]
     (doseq [layer s/LAYERS]
       (let [e (get layer ":layer/id")]
         (doseq [a layer-attrs]
           (when (contains? layer a)
             (conj! lines (str "[" e " " a " " (fmt (get layer a)) " " tx " :add]"))))
         (when (contains? layer ":layer/pr")
           (conj! lines (str "[" e " :layer/pr " (fmt (get layer ":layer/pr")) " " tx " :add]")))))
     (conj! lines "")
     (doseq [[sid suite] s/SUITES]
       (doseq [[a v] suite]
         (if (map? v)
           (doseq [[ka kv] v]
             (conj! lines (str "[" sid " " ka " " (fmt kv) " " tx " :add]")))
           (conj! lines (str "[" sid " " a " " (fmt v) " " tx " :add]")))))
     (conj! lines "")
     (conj! lines ";; ── DERIVED (transient — recompute on read, do not persist) ──")
     (doseq [[a v] (s/coverage-report)]
       (conj! lines (str "[:pq/coverage " a " " (fmt v) " " tx " :add] ;; :pq/is-transient true")))
     (str (str/join "\n" (persistent! lines)) "\n"))))
