(require
  hiolib.rule :readers * *
  hiolib.struct *)

(import
  traceback
  hiolib.stream *
  hiolib.struct *)

(setv debug False)

(defclass IndentPrinter []
  (defn #-- init [self [indent 0] [step 1] [char "\t"]]
    (setv self.indent indent
          self.step   step
          self.char   char))

  (defn #-- enter [self #* args #** kwargs]
    (+= self.indent self.step)
    self)

  (defn #-- exit [self #* args #** kwargs]
    (-= self.indent self.step)
    False)

  (defn [property] prefix [self]
    (* self.indent self.char))

  (defn print [self #* args #** kwargs]
    (print self.prefix #* args #** kwargs)))

(defclass DispMixin []
  (setv disp-whitelist None
        disp-blacklist None)

  (defn disp-attr-is-match [self attr rule-list default-pred]
    (for [rule rule-list]
      (ebranch (isinstance rule it)
               str   (when (= attr rule)
                       (break))
               tuple (ecase (len rule)
                            1 (let [#(name) rule]
                                (when (and (= attr name) (default-pred (getattr self name)))
                                  (break)))
                            2 (let [#(name pred) rule]
                                (when (and (= attr name) (pred (getattr self name)))
                                  (break)))))
      (else
        (return False)))
    (return True))

  (defn disp-attr-is-valid [self attr]
    (unless (is self.disp-whitelist None)
      (unless (.disp-attr-is-match self attr self.disp-whitelist bool)
        (return False)))
    (unless (is self.disp-blacklist None)
      (when (.disp-attr-is-match self attr self.disp-blacklist (fn [x] (not x)))
        (return False)))
    (return True))

  (defn [property] disp-all-attrs [self]
    (raise NotImplementedError))

  (defn [property] disp-attrs [self]
    (filter self.disp-attr-is-valid self.disp-all-attrs))

  (defn [property] disp-formatted-attrs [self]
    (gfor attr self.disp-attrs
          (.format "{}={}" attr (repr (getattr self attr)))))

  (defn [property] disp-inline-attrs-str [self]
    (.join "," self.disp-formatted-attrs))

  (defn [property] disp-inline-str [self]
    (.format "{}({})" (. self #-- class #-- name) self.disp-inline-attrs-str))

  (defn disp-print-attrs [self printer]
    (for [attr self.disp-formatted-attrs]
      (.print printer attr)))

  (defn disp-print [self printer]
    (.print printer (. self #-- class #-- name))
    (with [_ printer]
      (.disp-print-attrs self printer))))



(defclass Packet [DispMixin]
  (setv struct None)

  (defn #-- init [self]
    (setv self.next-packet None))

  (defn [property] last-packet [self]
    (if self.next-packet self.next-packet.last-packet self))

  (defn #-- truediv [self next-packet]
    (when (isinstance next-packet bytes)
      (setv next-packet (Payload :data next-packet)))
    (setv self.last-packet.next-packet next-packet)
    self)

  (defn #-- getitem [self i]
    (cond (isinstance i int)
          (cond (= i 0) self
                (and (> i 0) self.next-packet) (get self.next-packet (- i 1))
                True (raise IndexError))
          (isinstance i type)
          (cond (isinstance self i) self
                self.next-packet (get self.next-packet i)
                True (raise KeyError))))

  (defn #-- contains [self i]
    (bool (get self i)))

  (defn [property] disp-all-attrs [self]
    self.struct.names)

  (defn #-- str [self]
    (if self.next-packet
        (+ self.disp-inline-str "/" (str self.next-packet))
        self.disp-inline-str))

  (defn #-- repr [self]
    (str self))

  (defn print [self [printer None]]
    (unless printer
      (setv printer (IndentPrinter)))
    (.disp-print self printer)
    (when self.next-packet
      (.print self.next-packet printer)))

  (defn [property] parse-next-class [self])

  (defn [classmethod] parse [cls buf]
    (let [reader (BIOStream buf)
          packet (cls #** (dict (.zip cls.struct #* (.unpack-from-stream cls.struct reader))))
          buf (.read-all reader)]
      (when buf
        (setv packet.next-packet
              (let [next-class (or packet.parse-next-class Payload)]
                (try
                  (.parse next-class buf)
                  (except [e Exception]
                    (when debug
                      (print (.format "except while parsing {}: {}" (. next-class #-- name)  e))
                      (print (traceback.format-exc)))
                    (Payload :data buf))))))
      packet))

  (defn pre-build [self])

  (defn post-build [self])

  (defn build [self]
    (setv self.pload (if self.next-packet (.build self.next-packet) b""))
    (.pre-build self)
    (setv self.head (.pack self.struct #* (gfor name self.struct.names (getattr self name))))
    (.post-build self)
    (+ self.head self.pload))

  (defn #-- bytes [self]
    (.build self)))

(defstruct PayloadStruct [[all data]])

(defclass Payload [Packet]
  (setv struct PayloadStruct)

  (defn #-- init [self [data b""]]
    (#super-- init)
    (setv self.data data))

  (defn #-- str [self]
    (.format "Payload(len={},peek={})" (len self.data) (cut self.data 16)))

  (defn disp-print [self printer]
    (.print printer self)))

(defmacro defpacket [decorators name bases struct-fields fields #* body]
  (let [struct-name (hy.models.Symbol (+ (str name) "Struct"))
        fields (lfor field fields (if (isinstance field hy.models.Symbol) `[~field None] field))]
    `(do
       (defstruct ~struct-name
         ~struct-fields)
       (defclass [~@decorators] ~name [~@bases Packet]
         (setv struct ~struct-name)
         (defn #-- init [self ~@(gfor #(name default) fields `[~name ~default]) #** kwargs]
           (#super-- init #** kwargs)
           ~@(gfor #(name default) fields `(setv (. self ~name) ~name)))
         ~@body))))

(export
  :objects [Packet Payload]
  :macros [defpacket])
