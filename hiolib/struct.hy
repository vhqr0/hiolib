(require
  hiolib.rule :readers * *)

(import
  hiolib.stream *)

(defn normalize [v cls]
  (try (cls v) (except [Exception] v)))

(defn int-pack [i ilen [order "big"]]
  (.to-bytes i ilen order))

(defn int-unpack [b [order "big"]]
  (int.from-bytes b order))

(defn bits-pack [offsets bits ilen [order "big"]]
  (-> (cfor sum
            #(offset bit) (zip offsets bits)
            (<< bit offset))
      (int-pack ilen order)))

(defn bits-unpack [offsets masks b [order "big"]]
  (let [i (int-unpack b order)]
    (lfor #(offset mask) (zip offsets masks)
          (& (>> i offset) mask))))



(defclass StructValidationError [Exception])

(async-defclass Struct []
  (setv names None
        sync-struct None)

  (defn [classmethod] zip [cls #* args]
    (zip cls.names args))

  (async-defn [classmethod] pack-to-stream [cls writer #* args #** kwargs]
    (raise NotImplementedError))

  (async-defn [classmethod] unpack-from-stream [cls reader]
    (raise NotImplementedError))

  (async-defn [classmethod] pack-to-bytes [cls #* args #** kwargs]
    (let [writer ((async-name BIOStream))]
      (async-wait (.pack-to-stream cls writer #* args #** kwargs))
      (.getvalue writer)))

  (async-defn [classmethod] unpack-from-bytes [cls buf]
    (let [reader ((async-name BIOStream) buf)
          struct (async-wait (.unpack-from-stream cls reader))]
      (when (async-wait (.peek reader))
        (raise StructValidationError))
      struct))

  (defn [classmethod] pack [cls #* args #** kwargs]
    (.pack-to-bytes cls.sync-struct #* args #** kwargs))

  (defn [classmethod] unpack [cls buf]
    (.unpack-from-bytes cls.sync-struct buf))

  (async-defn [classmethod] pack-bytes-to-stream [cls writer #* args #** kwargs]
    (async-wait (.write writer (.pack cls #* args #** kwargs)))))



(defclass Field []
  (setv field-type-dict (dict)
        field-type None)

  (defn #-- init-subclass [cls]
    (when cls.field-type
      (setv (get cls.field-type-dict cls.field-type) cls)))

  (defn [classmethod] from-model [cls model]
    (let [model (#/ collections.deque model)
          type (.popleft model)
          name (.popleft model)
          meta (let [meta (dict)]
                 (while model
                   (let [k (.popleft model)
                         v (.popleft model)]
                     (setv (get meta (hy.mangle k.name)) v)))
                 meta)]
      ((get cls.field-type-dict type) :name name :meta meta)))

  (defn #-- init [self name meta]
    (setv self._name name self._meta meta))

  (defn #-- getattr [self name]
    (.get self._meta name))

  (defn [#/ functools.cached-property] names [self]
    (ebranch (isinstance self._name it)
             hy.models.Symbol [self._name]
             hy.models.List (#/ hyrule.flatten self._name)))

  (defn [#/ functools.cached-property] name [self]
    (ebranch (isinstance self._name it)
             hy.models.Symbol self._name
             hy.models.List (hy.models.Symbol
                              (+ "group-" (.join "-" (map str self.names))))))

  (defn [#/ functools.cached-property] group-struct [self]
    (when (isinstance self._name hy.models.List)
      (defn model-l2t [l]
        (hy.models.Tuple (gfor m l (if (isinstance m hy.models.List) (model-l2t m) m))))
      (model-l2t self._name)))

  (defn [property] from-field-form [self]
    (cond self.from
          self.from
          self.from-each
          `(let [them it] (lfor it them ~self.from-each))
          True
          'it))

  (defn [property] to-field-form [self]
    (cond self.to
          self.to
          self.to-each
          `(let [them it] (lfor it them ~self.to-each))
          True
          'it))

  (defn [property] from-bytes-1-form [self]
    (raise NotImplementedError))

  (defn [property] to-bytes-1-form [self]
    (raise NotImplementedError))

  (defn [property] from-bytes-form [self]
    (cond self.repeat
          `(lfor _ (range ~self.repeat) ~self.from-bytes-1-form)
          self.repeat-while
          `(let [them (list) it None]
             (while ~self.repeat-while
               (setv it ~self.from-bytes-1-form)
               (.append them it))
             them)
          self.repeat-do-until
          `(let [them (list) it None]
             (while True
               (setv it ~self.from-bytes-1-form)
               (.append them it)
               (when ~self.repeat-do-until
                 (break)))
             them)
          True
          self.from-bytes-1-form))

  (defn [property] to-bytes-form [self]
    (if (or self.repeat self.repeat-while self.repeat-do-until)
        `(let [them it]
           (for [it them]
             ~self.to-bytes-1-form))
        self.to-bytes-1-form))

  (defn [property] pack-setv-form [self]
    "
(let [it (let [it a] FROM-FIELD-FORM)] TO-BYTES-FORM)
(setv group-b-c #(b c))
(let [it (let [it group-b-c] FROM-FIELD-FORM)] TO-BYTES-FORM)
"
    `(do
       ~@(when self.group-struct
           `((setv ~self.name ~self.group-struct)))
       ~@(when self.from-validate
           `((let [it ~self.name]
               (unless ~self.from-validate
                 (raise StructValidationError)))))
       (let [it (let [it ~self.name] ~self.from-field-form)]
         ~self.to-bytes-form)))

  (defn [property] unpack-setv-form [self]
    "
(setv a (let [it FROM-BYTES-FORM] TO-FIELD-FORM))
(setv group-b-c (let [it FROM-BYTES-FORM] TO-FIELD-FORM))
(setv #(b c) group-b-c)
#(a b c ...)
"
    `(do
       (setv ~self.name (let [it ~self.from-bytes-form]
                          ~self.to-field-form))
       ~@(when self.group-struct
           `((setv ~self.group-struct ~self.name)))
       ~@(when self.to-validate
           `((let [it ~self.name]
               (unless ~self.to-validate
                 (raise StructValidationError))))))))



(defmacro defstruct [name fields]
  (let [fields (lfor field fields (#/ hiolib.struct.Field.from-model field))
        names (#/ functools.reduce #/ operator.add (gfor field fields field.names))]
    `(do
       (async-defclass ~name [(async-name Struct)]
         (setv names #(~@(gfor name names (hy.mangle (str name)))))
         (async-defn [classmethod] pack-to-stream [cls writer ~@names]
           ~@(gfor field fields field.pack-setv-form))
         (async-defn [classmethod] unpack-from-stream [cls reader]
           ~@(gfor field fields field.unpack-setv-form)
           #(~@names)))
       (setv (. ~name                                 sync-struct) ~name
             (. ~(#/ hiolib.rule.get-async-name name) sync-struct) ~name))))



(defclass AllField [Field]
  (setv field-type 'all)

  (defn [property] from-bytes-form [self]
    `(let [it (async-wait (.read-all reader))]
       ~(if self.struct `(.unpack ~self.struct it) 'it)))

  (defn [property] to-bytes-form [self]
    `(async-wait (.write writer ~(if self.struct `(.pack ~self.struct #* it) 'it)))))

(defclass BytesField [Field]
  (setv field-type 'bytes)

  (defn [property] from-bytes-1-form [self]
    `(let [it (async-wait (.read-exactly reader ~self.len))]
       ~(if self.struct `(.unpack ~self.struct it) 'it)))

  (defn [property] to-bytes-1-form [self]
    `(async-wait (.write writer ~(if self.struct `(.pack ~self.struct #* it) 'it)))))

(defclass IntField [Field]
  (setv field-type 'int)

  (defn [property] from-bytes-1-form [self]
    `(int-unpack (async-wait (.read-exactly reader ~self.len))
                 :order ~(or self.order "big")))

  (defn [property] to-bytes-1-form [self]
    `(async-wait (.write writer (int-pack it ~self.len :order ~(or self.order "big"))))))

(defclass VarLenField [Field]
  (setv field-type 'varlen)

  (defn [property] from-bytes-1-form [self]
    `(let [it (int-unpack (async-wait (.read-exactly reader ~self.len)) :order ~(or self.order "big"))]
       ~@(when self.len-to
           `((setv it ~self.len-to)))
       (let [it (async-wait (.read-exactly reader it))]
         ~(if self.struct `(.unpack ~self.struct it) 'it))))

  (defn [property] to-bytes-1-form [self]
    `(let [it ~(if self.struct `(.pack ~self.struct #* it) 'it)]
       (let [it (len it)]
         ~@(when self.len-from
             `((setv it ~self.len-from)))
         (async-wait (.write writer (int-pack it ~self.len :order ~(or self.order "big")))))
       (async-wait (.write writer it)))))

(defclass LineField [Field]
  (setv field-type 'line)

  (defn [property] from-bytes-1-form [self]
    `(.decode (async-wait (.read-line reader :sep ~self.sep))))

  (defn [property] to-bytes-1-form [self]
    `(async-wait (.write writer (+ (.encode it) ~self.sep)))))

(defclass BitsField [Field]
  (setv field-type 'bits)

  (defn [#/ functools.cached-property] int-lens [self]
    (list (map int self.lens)))

  (defn [#/ functools.cached-property] nbits [self]
    (sum self.int-lens))

  (defn [#/ functools.cached-property] nbytes [self]
    (let [#(d m) (divmod self.nbits 8)]
      (unless (= m 0)
        (raise ValueError))
      d))

  (defn [#/ functools.cached-property] offsets [self]
    (let [nbits self.nbits
          offsets (list)]
      (for [len self.int-lens]
        (-= nbits len)
        (.append offsets nbits))
      offsets))

  (defn [#/ functools.cached-property] masks [self]
    (lfor len self.int-lens (- (<< 1 len) 1)))

  (defn [property] from-bytes-1-form [self]
    `(bits-unpack #(~@self.offsets) #(~@self.masks)
                  (async-wait (.read-exactly reader ~self.nbytes))
                  :order ~(or self.order "big")))

  (defn [property] to-bytes-1-form [self]
    `(async-wait (.write writer (bits-pack #(~@self.offsets) it ~self.nbytes :order ~(or self.order "big"))))))

(defclass StructField [Field]
  (setv field-type 'struct)

  (defn [property] from-bytes-1-form [self]
    `(async-wait (.unpack-from-stream ~self.struct reader)))

  (defn [property] to-bytes-1-form [self]
    `(async-wait (.pack-to-stream ~self.struct writer #* it))))



(defmacro define-int-list-struct [struct-name field-name len-form #* args]
  `(defstruct ~struct-name
     [[int ~field-name
       :len ~len-form
       :repeat-while (async-wait (.peek reader))
       ~@args]]))

(defmacro define-list-struct [struct-name field-name struct-form #* args]
  `(defstruct ~struct-name
     [[struct ~field-name
       :struct ~struct-form
       :repeat-while (async-wait (.peek reader))
       ~@args]]))

(defmacro define-atom-list-struct [struct-name field-name struct-form #* args]
  `(defstruct ~struct-name
     [[struct ~field-name
       :struct ~struct-form
       :repeat-while (async-wait (.peek reader))
       :from-each #(it)
       :to-each (get it 0)
       ~@args]]))

(export
  :objects [normalize int-pack int-unpack bits-pack bits-unpack
            StructValidationError Struct AsyncStruct Field]
  :macros [defstruct define-int-list-struct define-list-struct define-atom-list-struct])
