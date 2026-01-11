(require
  hiolib.rule :readers * *
  hiolib.struct *
  hpacket.packet *)

(import
  socket
  ctypes [c-ushort]
  enum [IntEnum]
  traceback
  hiolib.stream *
  hiolib.struct *
  hpacket.packet
  hpacket.packet *)

(defn int-replace [buf offset ilen i]
  (+ (cut buf offset)
     (int-pack i ilen)
     (cut buf (+ offset ilen) None)))

(defclass RegistryDict []
  (defn #-- init-subclass [cls #* args #** kwargs]
    (#super-- init-subclass #* args #** kwargs)
    (setv cls._dict (dict)))

  (defn [classmethod] get [cls #* args]
    (.get cls._dict #* args))

  (defn [classmethod] register [cls #* keys]
    (defn wrapper [rcls]
      (for [key keys]
        (setv (get cls._dict key) rcls))
      rcls)
    wrapper)

  (defn [classmethod] resolve [cls obj]
    ;; resolve key of registered class instance obj
    (for [#(key rcls) (.items cls._dict)]
      (when (isinstance obj rcls)
        (return key)))))


;;; opt util
;;
;; opt: tuple[type: int, data: Any]
;; opts: list[opts]
;;
;; Opt:
;;   opt.pack-opt(data) => bytes
;;   opt.unpack-opt(bytes) => data
;;
;; Note that Opt may also a Struct, which used name pack/unpack.
;;
;; OptDict:
;;   opt-dict.pack(type, data) => opt.pack-opt(data) => bytes
;;   opt-dict.unpack(type, bytes) => opt.unpack-opt(bytes) => data
;;
;; OptDict usually is also a Enum of type, eg:
;;   FooOpt.pack(FooOpt.barType, data)
;;   FooOpt.unpack(FooOpt.barType, bytes)

(defclass DispOptsMixin []
  ;; print opts after all attrs
  (defn disp-print-attrs [self printer]
    (#super disp-print-attrs printer)
    (when self.opts
      (.print printer "opts={")
      (with [_ printer]
        (for [#(type data) self.opts]
          (if (isinstance data Packet)
              (do
                (.print printer (.format "{}:" (repr type)))
                (with [_ printer]
                  (.print data printer)))
              (.print printer (.format "{}: {}" (repr type) (repr data))))))
      (.print printer "}"))))

(defclass Opt []
  (defn [classmethod] pack-opt   [cls data] (raise NotImplementedError))
  (defn [classmethod] unpack-opt [cls data] (raise NotImplementedError)))

(defclass OptDict [RegistryDict]
  (defn [classmethod] pack [cls type data]
    (if (isinstance data bytes)
        data
        (let [opt-class (.get cls type)]
          (unless opt-class
            (raise KeyError))
          (.pack-opt opt-class data))))

  (defn [classmethod] unpack [cls type data]
    (let [opt-class (.get cls type)]
      (when opt-class
        (try
          (setv data (.unpack-opt opt-class data))
          (except [e Exception]
            (when hpacket.packet.debug
              (print (.format "except while parsing {}: {}" (. cls #-- name) e))
              (print (traceback.format-exc)))))))
    data))

(defmacro define-opt-dict [name enum-fields struct-fields]
  (let [struct-name (hy.models.Symbol (+ (str name) "Struct"))
        list-struct-name (hy.models.Symbol (+ (str name) "ListStruct"))]
    `(do
       (defclass ~name [OptDict IntEnum]
         (setv ~@enum-fields))
       (defstruct ~struct-name
         ~struct-fields)
       (define-list-struct ~list-struct-name
         opts
         (async-name ~struct-name)))))

(defclass IntOpt [Opt]
  (setv ilen None
        ecls None)

  (defn [classmethod] pack-opt [cls data]
    (int-pack data cls.ilen))

  (defn [classmethod] unpack-opt [cls data]
    (if (= (len data) cls.ilen)
        (let [i (int-unpack data)]
          (if cls.ecls (normalize i cls.ecls) i))
        data)))

(defmacro define-int-opt [name code ilen-form [ecls-form None]]
  (let [class-name (hy.models.Symbol (+ (str name) (str code)))]
    `(defclass
       [(.register ~name (. ~name ~code))]
       ~class-name [IntOpt]
       (setv ilen ~ilen-form)
       ~@(when ecls-form
           `((setv ecls ~ecls-form))))))

(defclass AtomStructOpt [Opt]
  (defn [classmethod] pack-opt [cls data]
    (.pack cls data))

  (defn [classmethod] unpack-opt [cls data]
    (get (.unpack cls data) 0)))

(defmacro define-atom-struct-opt [name code [struct-spec None]]
  (let [class-name (hy.models.Symbol (+ (str name) (str code)))
        struct-name (if (isinstance struct-spec hy.models.Symbol)
                        struct-spec
                        (hy.models.Symbol (+ (str name) (str code) "Struct")))]
    `(do
       ~@(when (and struct-spec (not (isinstance struct-spec hy.models.Symbol)))
           `((defstruct ~struct-name [~struct-spec])))
       (defclass
         [(.register ~name (.~name ~code))]
         ~class-name [AtomStructOpt ~struct-name]))))

(defclass StructOpt [Opt]
  (defn [classmethod] pack-opt [cls data]
    (.pack cls #* data))

  (defn [classmethod] unpack-opt [cls data]
    (.unpack cls data)))

(defmacro define-struct-opt [name code [struct-spec None]]
  (let [class-name (hy.models.Symbol (+ (str name) (str code)))
        struct-name (if (isinstance struct-spec hy.models.Symbol)
                        struct-spec
                        (hy.models.Symbol (+ (str name) (str code) "Struct")))]
    `(do
       ~@(when (and struct-spec (not (isinstance struct-spec hy.models.Symbol)))
           `((defstruct ~struct-name ~struct-spec)))
       (defclass
         [(.register ~name (.~name ~code))]
         ~class-name [StructOpt ~struct-name]))))

(defclass PacketOpt [Opt]
  (defn [classmethod] pack-opt [cls data]
    (.build data))

  (defn [classmethod] unpack-opt [cls data]
    (.parse cls data)))

(defmacro define-packet-opt [name code bases #* body]
  (let [class-name (hy.models.Symbol (+ (str name) (str code)))]
    `(defpacket
       [(.register ~name (. ~name ~code))]
       ~class-name [~@bases PacketOpt]
       ~@body)))


;;; proto util
;;
;; dispatch next packet by proto, eg. Ether.type, IPv4.Proto, IPv6.nh

(defclass ProtoDict [RegistryDict])

(defclass ProtoDispatchMixin []
  (setv proto-dict None
        proto-attr None)

  (defn [property] parse-next-class [self]
    (.get self.proto-dict (getattr self self.proto-attr)))

  (defn pre-build [self]
    (#super pre-build)
    (when (= (getattr self self.proto-attr) 0)
      (let [key (.resolve self.proto-dict self.next-packet)]
        (when key
          (setattr self self.proto-attr key))))))


;;; cksum util
;; there are two base mixins:
;;
;; CksumProxyMixin: proxy a cksum requirements to upper layer packets.
;;
;; CksumPloadMixin: if pload is an instance of CksumProxyMixin, then
;; calc cksum and fill corresponding field.

(defn cksum [buf]
  (when (& (len buf) 1)
    (+= buf b"\x00"))
  (let [s 0
        reader (BIOStream buf)]
    (while (.peek reader)
      (+= s (int-unpack (.read-exactly reader 2))))
    (setv s (+ (>> s 16) (& s 0xffff)))
    (setv s (+ (>> s 16) s))
    (&= s 0xffff)
    (. (c-ushort (- (- s) 1)) value)))

(defclass CksumProxyMixin []
  (setv cksum-packet None
        cksum-proto  None
        cksum-offset None
        cksum-start  None
        cksum-end    None))

(defclass CksumProxySelfMixin [CksumProxyMixin]
  (setv cksum-proto  None
        cksum-offset None)

  (defn post-build [self]
    (#super post-build)
    (setv self.cksum-packet self
          self.cksum-start  0
          self.cksum-end    (+ (len self.head) (len self.pload)))))

(defclass CksumProxyPloadMixin [CksumProxyMixin]
  (defn post-build [self]
    (#super post-build)
    (when (and (isinstance self.next-packet CksumProxyMixin)
               self.next-packet.cksum-packet)
      (setv self.cksum-packet self.next-packet.cksum-packet
            self.cksum-proto  self.next-packet.cksum-proto
            self.cksum-offset (+ (len self.head) self.next-packet.cksum-offset)
            self.cksum-start  (+ (len self.head) self.next-packet.cksum-start)
            self.cksum-end    (+ (len self.head) self.next-packet.cksum-end)))))

(defclass CksumPloadMixin []
  (defn cksum-phead [self buf proto]
    (raise NotImplementedError))

  (defn cksum-buf [self buf proto]
    (+ (.cksum-phead self buf proto) buf))

  (defn cksum-cksum [self buf proto]
    (cksum (.cksum-buf self buf proto)))

  (defn pre-build [self]
    (#super pre-build)
    (when (isinstance self.next-packet CksumProxyMixin)
      (let [packet self.next-packet.cksum-packet
            proto  self.next-packet.cksum-proto
            offset self.next-packet.cksum-offset
            start  self.next-packet.cksum-start
            end    self.next-packet.cksum-end]
        (when (and packet (= packet.cksum 0))
          (let [s (.cksum-cksum self (cut self.pload start end) proto)]
            (setv packet.cksum s
                  self.pload (int-replace self.pload offset 2 s))))))))


;;; common structs

(setv MAC-ZERO "00:00:00:00:00:00"
      IPv4-ZERO "0.0.0.0"
      IPv6-ZERO "::")

(defn mac-ntop [n]
  (.join ":" (gfor c n (.format "{:02x}" c))))

(defn mac-pton [p]
  (cfor bytes h (.split (.replace p "-" ":") ":") (int h 16)))

(defstruct MACAddr
  [[bytes addr
    :len 6
    :from (mac-pton it)
    :to (mac-ntop it)]])

(defstruct IPv4Addr
  [[bytes addr
    :len 4
    :from (socket.inet-pton socket.AF-INET it)
    :to (socket.inet-ntop socket.AF-INET it)]])

(defstruct IPv6Addr
  [[bytes addr
    :len 16
    :from (socket.inet-pton socket.AF-INET6 it)
    :to (socket.inet-ntop socket.AF-INET6 it)]])

(define-atom-list-struct MACAddrList  addrs (async-name MACAddr))
(define-atom-list-struct IPv4AddrList addrs (async-name IPv4Addr))
(define-atom-list-struct IPv6AddrList addrs (async-name IPv6Addr))

(defstruct IPv4CksumPhead
  [[struct [[src] [dst]] :struct (async-name IPv4Addr) :repeat 2]
   [int len :len 2]
   [int proto :len 2]])

(defstruct IPv6CksumPhead
  [[struct [[src] [dst]] :struct (async-name IPv6Addr) :repeat 2]
   [int len :len 2]
   [int proto :len 2]])

(defclass EtherType [ProtoDict IntEnum]
  (setv ARP  0x0806
        IPv4 0x0800
        IPv6 0x86dd))

(defclass IPProto [ProtoDict IntEnum]
  (setv NoNext   59
        Frag     44
        HBHOpts   0
        DestOpts 60
        ICMPv4    1
        ICMPv6   58
        TCP       6
        UDP      17))

(defpacket [] Ether [ProtoDispatchMixin]
  [[struct [[dst] [src]] :struct (async-name MACAddr) :repeat 2]
   [int type :len 2 :to (normalize it EtherType)]]
  [[dst MAC-ZERO] [src MAC-ZERO] [type 0]]

  (setv proto-attr "type"
        proto-dict EtherType))
