(require
  hiolib.rule :readers * *
  hiolib.struct *
  hiolib.packet *)

(import
  socket
  ctypes [c-ushort]
  enum [IntEnum]
  hiolib.stream *
  hiolib.struct *
  hiolib.packet *)

(defn int-replace [buf offset ilen i]
  (+ (cut buf offset)
     (int-pack i ilen)
     (cut buf (+ offset ilen) None)))

(defclass NextClassDict []
  (defn #-- init-subclass [cls #* args #** kwargs]
    (unless (hasattr cls "_dict")
      (setv cls._dict (dict))))

  (defn [classmethod] get [cls key]
    (.get cls._dict key))

  (defn [classmethod] resolve [cls next-packet]
    (for [#(key next-class) (.items cls._dict)]
      (when (isinstance next-packet next-class)
        (return key))))

  (defn [classmethod] register [cls key]
    (defn wrapper [next-class]
      (setv (get cls._dict key) next-class)
      next-class)
    wrapper))

(defclass NextClassMixin []
  (setv next-class-dict None
        next-class-attr None)

  (defn [property] next-class-key [self]
    (getattr self self.next-class-attr))

  (defn [property] parse-next-class [self]
    (.get self.next-class-dict self.next-class-key))

  (defn pre-build [self]
    (#super pre-build)
    (when (= self.next-class-key 0)
      (let [key (.resolve self.next-class-dict self.next-packet)]
        (unless (is key None)
          (setattr self self.next-class-attr key))))))

(defn cksum [buf]
  (when (& (len buf) 1)
    (+= buf b"\x00"))
  (let [s 0
        reader (BIOStreamReader buf)]
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
    (when (isinstance self.next-packet CksumProxyMixin)
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

(defclass EtherProto [NextClassDict IntEnum]
  (setv ARP  0x0806
        IPv4 0x0800
        IPv6 0x86dd))

(defclass IPProto [NextClassDict IntEnum]
  (setv Frag     44
        NoNext   59
        HBHOpts   0
        DestOpts 60
        ICMPv4    1
        ICMPv6   58
        TCP       6
        UDP      17))

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

(defstruct IPv4CksumPhead
  [[struct [[src] [dst]] :struct (async-name IPv4Addr) :repeat 2]
   [int len :len 2]
   [int proto :len 2]])

(defstruct IPv6CksumPhead
  [[struct [[src] [dst]] :struct (async-name IPv6Addr) :repeat 2]
   [int len :len 2]
   [int proto :len 2]])

(defpacket [] Ether [NextClassMixin]
  [[struct [[dst] [src]] :struct (async-name MACAddr) :repeat 2]
   [int proto :len 2]]
  [dst src [proto 0]]

  (setv next-class-attr "proto"
        next-class-dict EtherProto))

(defclass ARPOp [IntEnum]
  (setv Req 1 Rep 2))

(defpacket [(EtherProto.register EtherProto.ARP)] ARP []
  [[int hwtype :len 2]
   [int prototype :len 2]
   [int hwlen :len 1]
   [int protolen :len 1]
   [int op :len 2]
   [struct [hwsrc] :struct (async-name MACAddr)]
   [struct [protosrc] :struct (async-name IPv4Addr)]
   [struct [hwdst] :struct (async-name MACAddr)]
   [struct [protodst] :struct (async-name IPv4Addr)]]
  [[hwtype 1] [prototype EtherProto.IPv4] [hwlen 6] [protolen 4] [op ARPOp.Req]
   hwsrc protosrc hwdst protodst])

;;; used by IPv4Opt and TCPOpt
(defclass InetOptMixin []
  (defn [classmethod] unpack [cls buf]
    (unless (= (% (len buf) 4) 0)
      (raise ValueError))
    (let [opts (list)
          reader (BIOStreamReader buf)]
      (while (.peek reader)
        (let [opt (int-unpack (.read-exactly reader 1))]
          (cond (= opt cls.EOL)
                (.append opts #(cls.EOL b""))
                (= opt cls.NOP)
                (.append opts #(cls.NOP b""))
                True
                (let [opt (try (cls opt) (except [Exception] opt))
                      blen (int-unpack (.read-exactly reader 1))
                      buf (.read-exactly reader (- blen 2))]
                  (.append opts #(opt buf))))))
      opts))

  (defn [classmethod] pack [cls opts]
    (let [bufs (list)]
      (for [#(opt buf) opts]
        (.append bufs (int-pack opt 1))
        (unless (in opt #(cls.EOL cls.NOP))
          (.append bufs (int-pack (+ (len buf) 2) 1))
          (.append bufs buf)))
      (let [buf (.join b"" bufs)
            mod (% (len buf) 4)]
        (unless (= mod 0)
          (+= buf (bytes (- 4 mod))))
        buf))))

(defclass IPv4Opt [InetOptMixin IntEnum]
  (setv EOL 0 NOP 1))

(defpacket [(EtherProto.register EtherProto.IPv4)] IPv4
  ;; order is necessary: next class mixin should resolve proto first,
  ;; then cksum pload mixin can calculate phead
  [CksumPloadMixin NextClassMixin]
  [[bits [ver ihl] :lens [4 4]]
   [int tos :len 1]
   [int tlen :len 2]
   [int id :len 2]
   [bits [res DF MF offset] :lens [1 1 1 13]]
   [int ttl :len 1]
   [int proto :len 1]
   [int cksum :len 2]
   [struct [[src] [dst]] :struct (async-name IPv4Addr) :repeat 2]
   [bytes opts
    :len (* (- ihl 5) 4)
    :from (IPv4Opt.pack it)
    :to (IPv4Opt.unpack it)]]
  [[ver 4] [ihl 0] [tos 0] [tlen 0] [id 0]
   [res 0] [DF 0] [MF 0] [offset 0] [ttl 64]
   [proto 0] [cksum 0] src dst [opts #()]]

  (setv next-class-attr "proto"
        next-class-dict IPProto)

  (defn cksum-phead [self buf proto]
    (.pack IPv4CksumPhead self.src self.dst (len buf) proto))

  (defn post-build [self]
    (#super post-build)
    (when (= self.ihl 0)
      (setv self.ihl (// (len self.head) 4)
            self.head (int-replace self.head 0 1 (+ (<< self.ver 4) self.ihl))))
    (when (= self.tlen 0)
      (setv self.tlen (+ (len self.head) (len self.pload))
            self.head (int-replace self.head 2 2 self.tlen)))
    (when (= self.cksum 0)
      (setv self.cksum (cksum self.head)
            self.head (int-replace self.head 10 2 self.cksum)))))

(defclass IPv6Opt [IntEnum]
  (setv Pad1 0 PadN 1)

  (defn [classmethod] unpack [cls buf]
    (unless (= (% (+ (len buf) 2) 8) 0)
      (raise ValueError))
    (let [opts (list)
          reader (BIOStreamReader buf)]
      (while (.peek reader)
        (let [opt (int-unpack (.read-exactly reader 1))]
          (if (= opt cls.Pad1)
              (.append opts #(cls.Pad1 b""))
              (let [blen (int-unpack (.read-exactly reader 1))
                    buf (.read-exactly reader blen)]
                (.append opts #((if (= opt cls.PadN) cls.PadN opt) buf))))))
      opts))

  (defn [classmethod] pack [cls opts]
    (let [bufs (list)]
      (for [#(opt buf) opts]
        (.append bufs (int-pack opt 1))
        (unless (= opt cls.Pad1)
          (.append bufs (int-pack (len buf) 1))
          (.append bufs buf)))
      (let [buf (.join b"" bufs)
            mod (% (+ (len buf) 2) 8)]
        (unless (= mod 0)
          (let [n (- 8 mod)]
            (if (= n 1)
                (+= buf b"\x00")
                (+= buf b"\x01" (int-pack (- n 2) 1) (bytes (- n 2))))))
        buf))))

(defpacket [(EtherProto.register EtherProto.IPv6)] IPv6 [CksumPloadMixin NextClassMixin]
  [[bits [ver tc fl] :lens [4 8 20]]
   [int plen :len 2]
   [int nh :len 1]
   [int hlim :len 1]
   [struct [[src] [dst]] :struct (async-name IPv6Addr) :repeat 2]]
  [[ver 6] [tc 0] [fl 0] [plen 0] [nh 0] [hlim 64] src dst]

  (setv next-class-attr "nh"
        next-class-dict IPProto)

  (defn cksum-phead [self buf proto]
    (.pack IPv6CksumPhead self.src self.dst (len buf) proto))

  (defn pre-build [self]
    (#super pre-build)
    (when (= self.plen 0)
      (setv self.plen (len self.pload)))))

(defn ipv6-ext-datalen [elen]
  (- (* 8 (+ elen 1)) 2))

(defclass IPv6ExtMixin [CksumProxyPloadMixin NextClassMixin]
  (setv next-class-attr "nh"
        next-class-dict IPProto)

  (defn post-build [self]
    (#super post-build)
    (when (= self.elen 0)
      (setv self.elen (- (// (len self.head) 8) 1)
            self.head (int-replace self.head 1 1 self.elen)))))

(defpacket [(IPProto.register IPProto.Frag)] IPv6Frag
  ;; other than the following exts, frag ext has no elen fields,
  ;; therefore it isn't inherit from ipv6 ext mixin
  [CksumProxyPloadMixin NextClassMixin]
  [[int nh :len 1]
   [int res1 :len 1]
   [bits [offset res2 M] :lens [13 2 1]]
   [int id :len 4]]
  [[nh 0] [res1 0] [offset 0] [res2 0] [M 0] [id 0]]

  (setv next-class-attr "nh"
        next-class-dict IPProto))

(defpacket [(IPProto.register IPProto.NoNext)] IPv6NoNext [IPv6ExtMixin]
  [[int nh :len 1]
   [int elen :len 1]
   [int data :len (ipv6-ext-datalen elen)]]
  [[nh 0] [elen 0] [data b""]])

(defpacket [] IPv6Opts [IPv6ExtMixin]
  [[int nh :len 1]
   [int elen :len 1]
   [bytes opts
    :len (ipv6-ext-datalen elen)
    :from (IPv6Opt.pack it)
    :to (IPv6Opt.unpack it)]]
  [[nh 0] [elen 0] [opts #()]])

(defclass [(IPProto.register IPProto.HBHOpts)]  IPv6HBHOpts  [IPv6Opts])
(defclass [(IPProto.register IPProto.DestOpts)] IPv6DestOpts [IPv6Opts])

(defpacket [(IPProto.register IPProto.UDP)] UDP [CksumProxySelfMixin]
  [[int [src dst] :len 2 :repeat 2]
   [int len :len 2]
   [int cksum :len 2]]
  [src dst [len 0] [cksum 0]]

  (setv cksum-proto IPProto.UDP
        cksum-offset 6)

  (defn pre-build [self]
    (#super pre-build)
    (when (= self.len 0)
      (setv self.len (+ 8 (len self.pload))))))

(defclass TCPOpt [InetOptMixin IntEnum]
  (setv EOL  0
        NOP  1
        MSS  2
        WS   3
        SAOK 4
        SA   5
        TS   8))

(defpacket [(IPProto.register IPProto.TCP)] TCP [CksumProxySelfMixin]
  [[int [src dst] :len 2 :repeat 2]
   [int [seq ack] :len 4 :repeat 2]
   [bits [dataofs res C E U A P R S F] :lens [4 4 1 1 1 1 1 1 1 1]]
   [int win :len 2]
   [int cksum :len 2]
   [int uptr :len 2]
   [bytes opts
    :len (* (- dataofs 5) 4)
    :from (TCPOpt.pack it)
    :to (TCPOpt.unpack it)]]
  [src dst [seq 0] [ack 0] [dataofs 0]
   [res 0] [C 0] [E 0] [U 0] [A 0] [P 0] [R 0] [S 0] [F 0]
   [win 8192] [cksum 0] [uptr 0] [opts #()]]

  (setv cksum-proto IPProto.TCP
        cksum-offset 16)

  (defn post-build [self]
    (#super post-build)
    (when (= self.dataofs 0)
      (setv self.dataofs (// (len self.head) 4)
            self.head (int-replace self.head 12 1 (+ (<< self.dataofs 4) self.res))))))
