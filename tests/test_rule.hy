(require
  hiolib.rule :readers * *)

(import
  unittest [TestCase]
  asyncio
  hiolib.rule *)

(async-deffunc f []
  (async-if 'async 'sync))

(async-defclass B []
  (async-defn m [self]
    (async-wait ((async-name f)))))

(async-defclass C [(async-name B)]
  (async-defn m [self]
    (async-wait (#super m))))

(defclass TestRule [TestCase]
  (defn test-name [self]
    (.assertEqual self (get-async-name 'FooBar) 'AsyncFooBar)
    (.assertEqual self (get-async-name 'foo-bar) 'async-foo-bar)
    (.assertEqual self (get-async-name '_FooBar) '_AsyncFooBar)
    (.assertEqual self (get-async-name '_foo-bar) '_async-foo-bar))

  (defn test-func [self]
    (.assertEqual self (f) 'sync)
    (asyncio.run
      ((fn/a [] (.assertEqual self (await (async-f)) 'async)))))

  (defn test-class [self]
    (.assertEqual self (.m (C)) 'sync)
    (asyncio.run
      ((fn/a [] (.assertEqual self (await (.m (AsyncC))) 'async))))))
