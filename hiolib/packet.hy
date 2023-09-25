(require
  hiolib.rule :readers * *
  hiolib.struct *)

(import
  traceback
  hiolib.stream *
  hiolib.struct *)

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
    (let [s (. self #-- class #-- name)]
      (if self.next-packet (+ s "/" (str self.next-packet)) s)))

  (defn #-- repr [self]
    (str self))

  (defn [property] dict [self]
    (dfor name self.struct.names name (getattr self name)))

  (defn print [self]
    (print (. self #-- class))
    (print self.dict)
    (when (isinstance self.next-packet Packet)
      (.print self.next-packet)))

  (defn [property] parse-next-class [self])

  (defn [classmethod] parse [cls buf [debug False]]
    (let [reader (BIOStream buf)
          packet (cls #** (.unpack-dict-from-stream cls.struct reader))
          buf (.read-all reader)]
      (when buf
        (setv packet.next-packet
              (try
                (.parse (or packet.parse-next-class Payload) buf debug)
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
    (setv self.head (.pack-dict self.struct self.dict))
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
