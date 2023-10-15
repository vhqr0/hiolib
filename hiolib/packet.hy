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

(defclass Packet []
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

  (defn #-- getitem [self packet-class]
    (cond (isinstance self packet-class)
          self
          self.next-packet
          (get self.next-packet packet-class)))

  (defn #-- contains [self packet-class]
    (bool (get self packet-class)))

  (defn #-- str [self]
    (let [kwargs (.join "," (gfor kw self.struct.names (.format "{}={}" kw (repr (getattr self kw)))))
          s (.format "{}({})" (. self #-- class #-- name) kwargs)]
      (when self.next-packet
        (+= s "/" (str self.next-packet)))
      s))

  (defn #-- repr [self]
    (str self))

  (defn print-packet [self printer]
    (for [name self.struct.names]
      (.print printer (.format "{}: {}" name (repr (getattr self name))))))

  (defn print [self [printer None]]
    (unless printer
      (setv printer (IndentPrinter)))
    (.print printer (. self #-- class #-- name))
    (with [_ printer]
      (.print-packet self printer))
    (when self.next-packet
      (.print self.next-packet printer)))

  (defn [property] parse-next-class [self])

  (defn [classmethod] parse [cls buf]
    (let [reader (BIOStream buf)
          packet (cls #** (.unpack-dict-from-stream cls.struct reader))
          buf (.read-all reader)]
      (when buf
        (setv packet.next-packet
              (try
                (.parse (or packet.parse-next-class Payload) buf)
                (except [Exception]
                  (when debug
                    (print (traceback.format-exc)))
                  (Payload :data buf)))))
      packet))

  (defn pre-build [self])

  (defn post-build [self])

  (defn build [self]
    (setv self.pload (if self.next-packet (.build self.next-packet) b""))
    (.pre-build self)
    (setv self.head (.pack-dict self.struct (dfor name self.struct.names name (getattr self name))))
    (.post-build self)
    (+ self.head self.pload))

  (defn #-- bytes [self]
    (.build self)))

(defstruct PayloadStruct [[all data]])
(defclass Payload [Packet]
  (setv struct PayloadStruct)
  (defn #-- init [self [data b""]]
    (#super-- init)
    (setv self.data data)))

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
