(require
  hiolib.rule :readers * *)

(import
  hiolib.stream *)

(defn bytes-concat [bs]
  (.join b"" bs))

(defn int-pack [i ilen]
  (.to-bytes i ilen "big"))

(defn int-unpack [b]
  (int.from-bytes b "big"))

(defn bits-pack [offsets bits ilen]
  (-> (cfor sum
            #(offset bit) (zip offsets bits)
            (<< bit offset))
      (int-pack ilen)))

(defn bits-unpack [offsets masks b]
  (let [i (int-unpack b)]
    (lfor #(offset mask) (zip offsets masks)
          (& (>> i offset) mask))))

(defclass StructValidationError [Exception])

(async-defclass Struct []
  (setv names None)

  (defn [staticmethod] pack [#* args]
    (raise NotImplementedError))

  (async-defn [staticmethod] unpack-from-stream [reader]
    (raise NotImplementedError))

  (async-defn [classmethod] pack-dict [cls d]
    (.pack cls #* (gfor name cls.names (get d name))))

  (async-defn [classmethod] unpack-dict-from-stream [cls reader]
    (dict (zip cls.names (async-wait (.unpack-from-stream cls reader)))))

  (async-defn [classmethod] unpack [cls buf]
    (let [reader ((async-name BIOStreamReader) buf)
          st (async-wait (cls.unpack-from-stream reader))]
      (let [buf (async-wait (.peek reader))]
        (when (async-wait (.peek reader))
          (raise (IncompleteReadError 0 (len buf)))))
      st))

  (async-defn [classmethod] unpack-dict [cls buf]
    (dict (zip cls.names (async-wait (.unpack cls buf))))))

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

  (defn [#/ functools.cached-property] name-bytes [self]
    (hy.models.Symbol (+ (str self.name) "-bytes")))

  (defn [#/ functools.cached-property] group-struct [self]
    (when (isinstance self._name hy.models.List)
      (defn model-l2t [l]
        (hy.models.Tuple (gfor m l (if (isinstance m hy.models.List) (model-l2t m) m))))
      (model-l2t self._name)))

  (defn [property] from-field-form [self]
    (cond self.from
          `(let [it ~self.name] ~self.from)
          self.from-each
          `(lfor it ~self.name ~self.from-each)
          True
          self.name))

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
          self.repeat-until
          `(let [them (list)]
             (while True
               (let [it ~self.from-bytes-1-form]
                 (.append them it)
                 (when ~self.repeat-until
                   (break))))
             them)
          True
          self.from-bytes-1-form))

  (defn [property] to-bytes-form [self]
    (if (or self.repeat self.repeat-until)
        `(let [them it]
           (bytes-concat (gfor it them ~self.to-bytes-1-form)))
        self.to-bytes-1-form))

  (defn [property] pack-setv-form [self]
    "
(setv a-bytes (let [it FROM-FIELD-FORM] TO-BYTES-FORM))
(setv group-b-c #(b c))
(setv group-b-c-bytes (let [it FROM-FIELD-FORM] TO-BYTES-FORM))
(bytes-concat #(a-bytes group-b-c-bytes ...))
"
    `(do
       ~@(when self.group-struct
           `((setv ~self.name ~self.group-struct)))
       ~@(when self.from-validate
           `((let [it ~self.name]
               (unless ~self.from-validate
                 (raise StructValidationError)))))
       (setv ~self.name-bytes (let [it ~self.from-field-form]
                                ~self.to-bytes-form))))

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
        names (#/ functools.reduce #/ operator.add (gfor field fields field.names))
        names-bytes (lfor field fields field.name-bytes)]
    `(async-defclass ~name [(async-name Struct)]
       (setv names #(~@(gfor name names (hy.mangle (str name)))))
       (defn [staticmethod] pack [~@names]
         ~@(gfor field fields field.pack-setv-form)
         (bytes-concat #(~@names-bytes)))
       (async-defn [staticmethod] unpack-from-stream [reader]
         ~@(gfor field fields field.unpack-setv-form)
         #(~@names)))))

(defclass BytesField [Field]
  (setv field-type 'bytes)

  (defn [property] from-bytes-1-form [self]
    `(async-wait (.read-exactly reader ~self.len)))

  (defn [property] to-bytes-1-form [self]
    'it))

(defclass IntField [Field]
  (setv field-type 'int)

  (defn [property] from-bytes-1-form [self]
    `(int-unpack (async-wait (.read-exactly reader ~self.len))))

  (defn [property] to-bytes-1-form [self]
    `(int-pack it ~self.len)))

(defclass VarLenField [Field]
  (setv field-type 'varlen)

  (defn [property] from-bytes-1-form [self]
    `(let [_len (int-unpack (async-wait (.read-exactly reader ~self.len)))]
       (async-wait (.read-exactly reader _len))))

  (defn [property] to-bytes-1-form [self]
    `(+ (int-pack (len it) ~self.len) it)))

(defclass LineField [Field]
  (setv field-type 'line)

  (defn [property] from-bytes-1-form [self]
    `(.decode (async-wait (.read-line reader :sep ~self.sep))))

  (defn [property] to-bytes-1-form [self]
    `(+ (.encode it) ~self.sep)))

(defclass BitsField [Field]
  (setv field-type 'bits)

  (defn [property] _lens [self]
    (map int self.lens))

  (defn [property] sum [self]
    (sum self._lens))

  (defn [property] len [self]
    (let [#(d m) (divmod self.sum 8)]
      (unless (= m 0)
        (raise ValueError))
      d))

  (defn [property] offsets [self]
    (let [sum self.sum
          offsets (list)]
      (for [len self._lens]
        (-= sum len)
        (.append offsets sum))
      offsets))

  (defn [property] masks [self]
    (lfor len self._lens (- (<< 1 len) 1)))

  (defn [property] from-bytes-1-form [self]
    `(bits-unpack #(~@self.offsets) #(~@self.masks) (async-wait (.read-exactly reader ~self.len))))

  (defn [property] to-bytes-1-form [self]
    `(bits-pack #(~@self.offsets) it ~self.len)))

(defclass StructField [Field]
  (setv field-type 'struct)

  (defn [property] from-bytes-1-form [self]
    `(async-wait (.unpack-from-stream ~self.struct reader)))

  (defn [property] to-bytes-1-form [self]
    `(.pack ~self.struct #* it)))

(export
  :objects [bytes-concat int-pack int-unpack bits-pack bits-unpack
            StructValidationError Struct AsyncStruct Field]
  :macros [defstruct])
