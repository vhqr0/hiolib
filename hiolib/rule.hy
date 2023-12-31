(require
  hyrule :readers * *)

(import
  hyrule *)

(defreader --
  (.slurp-space &reader)
  (hy.models.Symbol (.format "__{}__" (.read-ident &reader))))

(defreader super
  (.slurp-space &reader)
  `(. (super) ~(hy.models.Symbol (.read-ident &reader))))

(defreader super--
  (.slurp-space &reader)
  `(. (super) ~(hy.models.Symbol (.format "__{}__" (.read-ident &reader)))))

(setv async? True)

(defn get-async-name [name]
  ;; 'FooBar   => 'AsyncFooBar
  ;; 'foo-bar  => 'async-foo-bar
  ;; '_FooBar  => '_AsyncFooBar
  ;; '_foo-bar => '_async-foo-bar
  (let [name (str name)
        isprivate (.startswith name "_")
        islower (.islower name)]
    (hy.models.Symbol (+ (if isprivate "_" "") (if islower "async-" "Async") (.lstrip name "_")))))

(defmacro async-if [async-form sync-form]
  (if #/ hiolib.rule.async? async-form sync-form))

(defmacro async-name [name]
  `(async-if ~(#/ hiolib.rule.get-async-name name) ~name))

(defmacro async-wait [coro-form]
  `(async-if (await ~coro-form) ~coro-form))

(defmacro async-iter [coro-form]
  `((async-if aiter iter) ~coro-form))

(defmacro async-next [coro-form]
  `((async-if anext next) ~coro-form))

(defmacro async-for [bracket #* body]
  `(async-if (for [:async ~@bracket] ~@body) (for [~@bracket] ~@body)))

(defmacro async-with [#* body]
  `(async-if (with/a ~@body) (with ~@body)))

(defmacro async-fn [#* body]
  `(async-if (fn/a ~@body) (fn ~@body)))

(defmacro async-defn [#* body]
  `(async-if (defn/a ~@body) (defn ~@body)))

(defmacro async-defclass [#* body]
  (let [body (#/ collections.deque body)
        decorators (if (isinstance (get body 0) hy.models.List) (.popleft body) '[])
        name (.popleft body)]
    `(do
       (eval-when-compile (setv #/ hiolib.rule.async? False))
       (defclass ~decorators ~name ~@body)
       (eval-when-compile (setv #/ hiolib.rule.async? True))
       (defclass ~decorators ~(#/ hiolib.rule.get-async-name name) ~@body))))

(defmacro async-deffunc [#* body]
  (let [body (#/ collections.deque body)
        decorators (if (isinstance (get body 0) hy.models.List) (.popleft body) '[])
        name (.popleft body)]
    `(do
       (eval-when-compile (setv #/ hiolib.rule.async? False))
       (defn ~decorators ~name ~@body)
       (eval-when-compile (setv #/ hiolib.rule.async? True))
       (defn/a ~decorators ~(#/ hiolib.rule.get-async-name name) ~@body))))
