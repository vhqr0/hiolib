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

(defn enumlize [e enum-class]
  (try (enum-class e) (except [Exception] e)))

(defn int-replace [buf offset ilen i]
  (+ (cut buf offset)
     (int-pack i ilen)
     (cut buf (+ offset ilen) None)))

(defclass Opt []
  (defn [classmethod] pack-data [cls data]
    (raise NotImplementedError))

  (defn [classmethod] unpack-data [cls data]
    (raise NotImplementedError)))

(defclass IntOpt [Opt]
  (setv ilen None
        enum-class None)

  (defn [classmethod] pack-data [cls data]
    (int-pack data cls.ilen))

  (defn [classmethod] unpack-data [cls data]
    (if (= (len data) cls.ilen)
        (let [i (int-unpack data)]
          (if cls.enum-class (enumlize i cls.enum-class) i))
        data)))

(defclass SpliceStructOpt [Opt]
  (defn [classmethod] pack-data [cls data]
    (.pack cls data))

  (defn [classmethod] unpack-data [cls data]
    (get (.unpack cls data) 0)))

(defclass StructOpt [Opt]
  (defn [classmethod] pack-data [cls data]
    (.pack cls #* data))

  (defn [classmethod] unpack-data [cls data]
    (.unpack cls data)))

(defclass PacketOpt [Opt]
  (defn [classmethod] pack-data [cls data]
    (.build data))

  (defn [classmethod] unpack-data [cls data]
    (.parse cls data)))

(defclass OptDict []
  (defn #-- init-subclass [cls #* args #** kwargs]
    (#super-- init-subclass #* args #** kwargs)
    (setv cls._dict (dict)))

  (defn [classmethod] register [cls #* types]
    (defn wrapper [opt-class]
      (for [type types]
        (setv (get cls._dict type) opt-class))
      opt-class)
    wrapper)

  (defn [classmethod] pack-data [cls type data]
    (if (isinstance data bytes) data (.pack-data (.get cls._dict type) data)))

  (defn [classmethod] unpack-data [cls type data]
    (let [opt-class (.get cls._dict type)]
      (when opt-class
        (try
          (setv data (.unpack-data opt-class data))
          (except [Exception]))))
    data)

  (defn [classmethod] get-struct [cls]
    (raise NotImplementedError))

  (defn [classmethod] get-opt [cls #* fields]
    (raise NotImplementedError))

  (defn [classmethod] get-fields [cls #* opt]
    (raise NotImplementedError))

  (defn [classmethod] pack-opt [cls opt]
    (let [#(type #* args data) opt]
      (.pack (.get-struct cls) #* (.get-fields cls type #* args (.pack-data cls type data)))))

  (defn [classmethod] pack [cls opts]
    (.join b"" (gfor opt opts (.pack-opt cls opt))))

  (defn [classmethod] unpack-opt-from-stream [cls reader]
    (let [fields (.unpack-from-stream (.get-struct cls) reader)
          #(type #* args data) (.get-opt cls #* fields)]
      #((enumlize type cls) #* args (.unpack-data cls type data))))

  (defn [classmethod] unpack [cls buf]
    (let [reader (BIOStream buf)
          opts (list)]
      (while (.peek reader)
        (.append opts (.unpack-opt-from-stream cls reader)))
      opts)))

(defclass NextClassDict []
  (defn #-- init-subclass [cls #* args #** kwargs]
    (setv cls._dict (dict)))

  (defn [classmethod] get [cls key]
    (.get cls._dict key))

  (defn [classmethod] resolve [cls next-packet]
    (for [#(key next-class) (.items cls._dict)]
      (when (isinstance next-packet next-class)
        (return key))))

  (defn [classmethod] register [cls #* keys]
    (defn wrapper [next-class]
      (for [key keys]
        (setv (get cls._dict key) next-class))
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

(defstruct MACAddrs
  [[struct addrs
    :struct (async-name MACAddr)
    :repeat-until (not (async-wait (.peek reader)))
    :to-each (get it 0)
    :from-each #(it)]])

(defstruct IPv4Addrs
  [[struct addrs
    :struct (async-name IPv4Addr)
    :repeat-until (not (async-wait (.peek reader)))
    :to-each (get it 0)
    :from-each #(it)]])

(defstruct IPv6Addrs
  [[struct addrs
    :struct (async-name IPv6Addr)
    :repeat-until (not (async-wait (.peek reader)))
    :to-each (get it 0)
    :from-each #(it)]])

(defstruct IPv4CksumPhead
  [[struct [[src] [dst]] :struct (async-name IPv4Addr) :repeat 2]
   [int len :len 2]
   [int proto :len 2]])

(defstruct IPv6CksumPhead
  [[struct [[src] [dst]] :struct (async-name IPv6Addr) :repeat 2]
   [int len :len 2]
   [int proto :len 2]])

(defclass EtherType [NextClassDict IntEnum]
  (setv ARP  0x0806
        IPv4 0x0800
        IPv6 0x86dd))

(defpacket [] Ether [NextClassMixin]
  [[struct [[dst] [src]] :struct (async-name MACAddr) :repeat 2]
   [int type :len 2 :to (enumlize it EtherType)]]
  [[dst MAC-ZERO] [src MAC-ZERO] [type 0]]

  (setv next-class-attr "type"
        next-class-dict EtherType))

(defclass IPProto [NextClassDict IntEnum]
  (setv NoNext   59
        Frag     44
        HBHOpts   0
        DestOpts 60
        ICMPv4    1
        ICMPv6   58
        TCP       6
        UDP      17))

(defstruct InetOptStruct
  [[int type :len 1]
   [int olen :len (if (in type #(0 1)) 0 1)]
   [bytes data :len (if (in type #(0 1)) 0 (- olen 2))]])

;;; inherited by IPv4Opt and TCPOpt
(defclass InetOpt [OptDict]
  (defn [classmethod] get-struct [cls]
    InetOptStruct)

  (defn [classmethod] get-opt [cls type olen data]
    #(type data))

  (defn [classmethod] get-fields [cls type data]
    #(type (if (in type #(0 1)) 0 (+ (len data) 2)) data))

  (defn [classmethod] pack [cls opts]
    (let [buf (#super pack opts)
          mod (% (len buf) 4)]
      (if (= mod 0)
          buf
          (+ buf (bytes (- 4 mod)))))))

(defclass IPv4Opt [InetOpt IntEnum]
  (setv EOL 0 NOP 1))

(defpacket [(EtherType.register EtherType.IPv4)] IPv4
  ;; order is necessary: next class mixin should resolve proto first,
  ;; then cksum pload mixin can calculate phead
  [CksumPloadMixin NextClassMixin]
  [[bits [ver ihl] :lens [4 4]]
   [int tos :len 1]
   [int tlen :len 2]
   [int id :len 2]
   [bits [res DF MF offset] :lens [1 1 1 13]]
   [int ttl :len 1]
   [int proto :len 1 :to (enumlize it IPProto)]
   [int cksum :len 2]
   [struct [[src] [dst]] :struct (async-name IPv4Addr) :repeat 2]
   [bytes opts
    :len (* (- ihl 5) 4)
    :from (IPv4Opt.pack it)
    :to (IPv4Opt.unpack it)]]
  [[ver 4] [ihl 0] [tos 0] [tlen 0] [id 0]
   [res 0] [DF 0] [MF 0] [offset 0] [ttl 64]
   [proto 0] [cksum 0] [src IPv4-ZERO] [dst IPv4-ZERO] [opts #()]]

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

(defstruct IPv6OptStruct
  [[int type :len 1]
   [int dlen :len (if (= type 0) 0 1)]
   [bytes data :len dlen]])

(defclass IPv6Opt [OptDict IntEnum]
  (setv Pad1 0 PadN 1)

  (defn [classmethod] get-struct [cls]
    IPv6OptStruct)

  (defn [classmethod] get-opt [cls type dlen data]
    #(type data))

  (defn [classmethod] get-fields [cls type data]
    #(type (len data) data))

  (defn [classmethod] pack [cls opts]
    (let [buf (#super pack opts)
          mod (% (+ (len buf) 2) 8)]
      (cond (= mod 0)
            buf
            (= mod 7)
            (+ buf b"\x00")
            True
            (let [n (- 6 mod)]
              (+ buf b"\x01" (int-pack n 1) (bytes n)))))))

(defstruct IPv6OptPadNStruct
  [[all pad
    :from (bytes (- it 2))
    :to (+ (len it) 2)]])

(defclass [(IPv6Opt.register IPv6Opt.PadN)] IPv6OptPadN [SpliceStructOpt IPv6OptPadNStruct])

(defpacket [(EtherType.register EtherType.IPv6)] IPv6 [CksumPloadMixin NextClassMixin]
  [[bits [ver tc fl] :lens [4 8 20]]
   [int plen :len 2]
   [int nh :len 1 :to (enumlize it IPProto)]
   [int hlim :len 1]
   [struct [[src] [dst]] :struct (async-name IPv6Addr) :repeat 2]]
  [[ver 6] [tc 0] [fl 0] [plen 0] [nh 0] [hlim 64] [src IPv6-ZERO] [dst IPv6-ZERO]]

  (setv next-class-attr "nh"
        next-class-dict IPProto)

  (defn cksum-phead [self buf proto]
    (.pack IPv6CksumPhead self.src self.dst (len buf) proto))

  (defn pre-build [self]
    (#super pre-build)
    (when (= self.plen 0)
      (setv self.plen (len self.pload)))))

(defpacket [(IPProto.register IPProto.Frag)] IPv6Frag
  ;; other than the following exts, frag ext has no elen fields,
  ;; therefore it isn't inherit from ipv6 ext mixin
  [CksumProxyPloadMixin NextClassMixin]
  [[int nh :len 1 :to (enumlize it IPProto)]
   [int res1 :len 1]
   [bits [offset res2 M] :lens [13 2 1]]
   [int id :len 4]]
  [[nh 0] [res1 0] [offset 0] [res2 0] [M 0] [id 0]]

  (setv next-class-attr "nh"
        next-class-dict IPProto))

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

(defpacket [] IPv6Opts [IPv6ExtMixin]
  [[int nh :len 1 :to (enumlize it IPProto)]
   [int elen :len 1]
   [bytes opts
    :len (ipv6-ext-datalen elen)
    :from (IPv6Opt.pack it)
    :to (IPv6Opt.unpack it)]]
  [[nh 0] [elen 0] [opts #()]])

(defclass [(IPProto.register IPProto.HBHOpts)]  IPv6HBHOpts  [IPv6Opts])
(defclass [(IPProto.register IPProto.DestOpts)] IPv6DestOpts [IPv6Opts])

(defclass ARPOp [IntEnum]
  (setv Req 1 Rep 2))

(defpacket [(EtherType.register EtherType.ARP)] ARP []
  [[int hwtype :len 2]
   [int prototype :len 2]
   [int hwlen :len 1]
   [int protolen :len 1]
   [int op :len 2 :to (enumlize it ARPOp)]
   [struct [hwsrc] :struct (async-name MACAddr)]
   [struct [protosrc] :struct (async-name IPv4Addr)]
   [struct [hwdst] :struct (async-name MACAddr)]
   [struct [protodst] :struct (async-name IPv4Addr)]]
  [[hwtype 1] [prototype EtherType.IPv4] [hwlen 6] [protolen 4] [op ARPOp.Req]
   [hwsrc MAC-ZERO] [protosrc IPv4-ZERO] [hwdst MAC-ZERO] [protodst IPv4-ZERO]])

(defclass IPv4Error [IPv4])
(defclass IPv6Error [IPv6])

(defclass ICMPv4Type [NextClassDict IntEnum]
  (setv EchoReq       8
        EchoRep       0
        DestUnreach   3
        TimeExceeded 11
        ParamProblem 12
        Redirect      5))

(defclass ICMPv6Type [NextClassDict IntEnum]
  (setv EchoReq      128
        EchoRep      129
        DestUnreach    1
        PacketTooBig   2
        TimeExceeded   3
        ParamProblem   4
        NDRS         133
        NDRA         134
        NDNS         135
        NDNA         136
        NDRM         137))

(defpacket [(IPProto.register IPProto.ICMPv4)] ICMPv4 [NextClassMixin]
  [[int type :len 1 :to (enumlize it ICMPv4Type)]
   [int code :len 1]
   [int cksum :len 2]]
  [[type 0] [code 0] [cksum 0]]

  (setv next-class-attr "type"
        next-class-dict ICMPv4Type)

  (defn post-build [self]
    (#super post-build)
    (when (= self.cksum 0)
      (setv self.cksum (cksum (+ self.head self.pload))
            self.head (int-replace self.head 2 2 self.cksum)))))

(defpacket [] ICMPv4Echo []
  [[int [id seq] :len 2 :repeat 2]]
  [[id 0] [seq 0]])

(defclass [(ICMPv4Type.register ICMPv4Type.EchoReq)] ICMPv4EchoReq [ICMPv4Echo])
(defclass [(ICMPv4Type.register ICMPv4Type.EchoRep)] ICMPv4EchoRep [ICMPv4Echo])

(defclass ICMPv4WithPacketMixin []
  (defn [property] parse-next-class [self] IPv4Error))

(defpacket [] ICMPv4WithPacket [ICMPv4WithPacketMixin]
  [[int unused :len 4]]
  [[unused 0]])

(defpacket [] ICMPv4WithPacketPTR [ICMPv4WithPacketMixin]
  [[int ptr :len 1] [int unused :len 3]]
  [[ptr 0] [unused 0]])

(defpacket [] ICMPv4WithPacketAddr [ICMPv4WithPacketMixin]
  [[struct [addr] :struct (async-name IPv4Addr)]]
  [[addr IPv4-ZERO]])

(defclass [(ICMPv4Type.register ICMPv4Type.DestUnreach)]  ICMPv4DestUnreach  [ICMPv4WithPacket])
(defclass [(ICMPv4Type.register ICMPv4Type.TimeExceeded)] ICMPv4TimeExceeded [ICMPv4WithPacket])
(defclass [(ICMPv4Type.register ICMPv4Type.ParamProblem)] ICMPv4ParamProblem [ICMPv4WithPacketPTR])
(defclass [(ICMPv4Type.register ICMPv4Type.Redirect)]     ICMPv4Redirect     [ICMPv4WithPacketAddr])

(defpacket [(IPProto.register IPProto.ICMPv6)] ICMPv6 [CksumProxySelfMixin NextClassMixin]
  [[int type :len 1 :to (enumlize it ICMPv6Type)]
   [int code :len 1]
   [int cksum :len 2]]
  [[type 0] [code 0] [cksum 0]]

  (setv next-class-attr "type"
        next-class-dict ICMPv6Type)

  (setv cksum-proto  IPProto.ICMPv6
        cksum-offset 2))

(defpacket [] ICMPv6Echo []
  [[int [id seq] :len 2 :repeat 2]]
  [[id 0] [seq 0]])

(defclass [(ICMPv6Type.register ICMPv6Type.EchoReq)] ICMPv6EchoReq [ICMPv6Echo])
(defclass [(ICMPv6Type.register ICMPv6Type.EchoRep)] ICMPv6EchoRep [ICMPv6Echo])

(defclass ICMPv6WithPacketMixin []
  (defn [property] parse-next-class [self] IPv6Error))

(defpacket [] ICMPv6WithPacket [ICMPv6WithPacketMixin]
  [[int unused :len 4]]
  [[unused 0]])

(defpacket [] ICMPv6WithPacketMTU [ICMPv6WithPacketMixin]
  [[int mtu :len 4]]
  [[mtu 1280]])

(defpacket [] ICMPv6WithPacketPTR [ICMPv6WithPacketMixin]
  [[int ptr :len 4]]
  [[ptr 0]])

(defclass [(ICMPv6Type.register ICMPv6Type.DestUnreach)]  ICMPv6DestUnreach  [ICMPv6WithPacket])
(defclass [(ICMPv6Type.register ICMPv6Type.PacketTooBig)] ICMPv6PacketTooBig [ICMPv6WithPacketMTU])
(defclass [(ICMPv6Type.register ICMPv6Type.TimeExceeded)] ICMPv6TimeExceeded [ICMPv6WithPacket])
(defclass [(ICMPv6Type.register ICMPv6Type.ParamProblem)] ICMPv6ParamProblem [ICMPv6WithPacketPTR])

(defstruct ICMPv6NDOptStruct
  [[int type :len 1]
   [int olen :len 1]
   [bytes data :len (- (* 8 olen) 2)]])

(defclass ICMPv6NDOpt [OptDict IntEnum]
  (setv SrcAddr 1
        DstAddr 2
        Prefix  3
        RMHead  4
        MTU     5)

  (defn [classmethod] get-struct [self]
    ICMPv6NDOptStruct)

  (defn [classmethod] get-opt [cls type olen data]
    #(type data))

  (defn [classmethod] get-fields [cls type data]
    #(type (// (+ (len data) 2) 8) data)))

(defstruct ICMPv6NDOptsStruct
  [[all opts
    :from (ICMPv6NDOpt.pack it)
    :to (ICMPv6NDOpt.unpack it)]])

(defpacket [(ICMPv6Type.register ICMPv6Type.NDRS)] ICMPv6NDRS []
  [[int res :len 4]
   [struct [opts] :struct (async-name ICMPv6NDOptsStruct)]]
  [[res 0] [opts #()]])

(defpacket [(ICMPv6Type.register ICMPv6Type.NDRA)] ICMPv6NDRA []
  [[int hlim :len 1]
   [bits [M O res] :lens [1 1 6]]
   [int routerlifetime :len 2]
   [int reachabletime :len 4]
   [int retranstimer :len 4]
   [struct [opts] :struct (async-name ICMPv6NDOptsStruct)]]
  [[hlim 0] [M 0] [O 0] [res 0] [routerlifetime 1800]
   [reachabletime 0] [retranstimer 0] [opts #()]])

(defpacket [(ICMPv6Type.register ICMPv6Type.NDNS)] ICMPv6NDNS []
  [[int res :len 4]
   [struct [tgt] :struct (async-name IPv6Addr)]
   [struct [opts] :struct (async-name ICMPv6NDOptsStruct)]]
  [[res 0] [tgt IPv6-ZERO] [opts #()]])

(defpacket [(ICMPv6Type.register ICMPv6Type.NDNA)] ICMPv6NDNA []
  [[bits [R S O res] :lens [1 1 1 29]]
   [struct [tgt] :struct (async-name IPv6Addr)]
   [struct [opts] :struct (async-name ICMPv6NDOptsStruct)]]
  [[R 0] [S 0] [O 0] [res 0] [tgt IPv6-ZERO] [opts #()]])

(defpacket [(ICMPv6Type.register ICMPv6Type.NDRM)] ICMPv6NDRM []
  [[int res :len 4]
   [struct [[tgt] [dst]] :struct (async-name IPv6Addr) :repeat 2]
   [struct [opts] :struct (async-name ICMPv6NDOptsStruct)]]
  [[res 0] [tgt IPv6-ZERO] [dst IPv6-ZERO] [opts #()]])

(defclass [(ICMPv6NDOpt.register ICMPv6NDOpt.SrcAddr)] ICMPv6NDOptSrcAddr [SpliceStructOpt MACAddr])
(defclass [(ICMPv6NDOpt.register ICMPv6NDOpt.DstAddr)] ICMPv6NDOptDstAddr [SpliceStructOpt MACAddr])

(defpacket [(ICMPv6NDOpt.register ICMPv6NDOpt.Prefix)] ICMPv6NDOptPrefix [PacketOpt]
  [[int plen :len 1]
   [bits [L A res1] :lens [1 1 6]]
   [int validlifetime :len 4]
   [int preferredtime :len 4]
   [int res2 :len 4]
   [struct [prefix] :struct (async-name IPv6Addr)]]
  [[plen 64] [L 0] [A 0] [res1 0]
   [validlifetime 0xffffffff] [preferredtime 0xffffffff]
   [res2 0] [prefix IPv6-ZERO]])

(defpacket [(ICMPv6NDOpt.register ICMPv6NDOpt.RMHead)] ICMPv6NDOptRMHead [PacketOpt]
  [[int res :len 6]]
  [[res 0]]
  (defn [property] parse-next-class [self] IPv6Error))

(defclass [(ICMPv6NDOpt.register ICMPv6NDOpt.MTU)] ICMPv6NDOptMTU [IntOpt]
  (setv ilen 6))

(defclass UDPService [NextClassDict IntEnum]
  (setv DNS         53
        MDNS      5353
        LLMNR     5355
        DHCPv4Cli   67
        DHCPv4Srv   68
        DHCPv6Cli  546
        DHCPv6Srv  547))

(defpacket [(IPProto.register IPProto.UDP)] UDP [CksumProxySelfMixin]
  [[int [src dst] :len 2 :repeat 2]
   [int len :len 2]
   [int cksum :len 2]]
  [[src 0] [dst 0] [len 0] [cksum 0]]

  (setv cksum-proto IPProto.UDP
        cksum-offset 6)

  (defn [property] parse-next-class [self]
    (or (.get UDPService self.dst)
        (.get UDPService self.src)))

  (defn pre-build [self]
    (#super pre-build)
    (when (= self.len 0)
      (setv self.len (+ 8 (len self.pload))))))

(defclass TCPOpt [InetOpt IntEnum]
  (setv EOL    0
        NOP    1
        MSS    2
        WS     3
        SAckOK 4
        SAck   5
        TS     8))

(defclass [(TCPOpt.register TCPOpt.MSS)] TCPOptMSS [IntOpt]
  (setv ilen 2))

(defclass [(TCPOpt.register TCPOpt.WS)] TCPOptWS [IntOpt]
  (setv ilen 1))

(defstruct TCPOptSAckStruct
  [[int edges :len 4 :repeat-until (not (async-wait (.peek reader)))]])

(defclass [(TCPOpt.register TCPOpt.SAck)] TCPOptSAck [SpliceStructOpt TCPOptSAckStruct])

(defstruct TCPOptTSStruct
  [[int tsval :len 4]
   [int tsecr :len 4]])

(defclass [(TCPOpt.register TCPOpt.TS)] TCPOptTS [StructOpt TCPOptTSStruct])

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
  [[src 0] [dst 0] [seq 0] [ack 0] [dataofs 0]
   [res 0] [C 0] [E 0] [U 0] [A 0] [P 0] [R 0] [S 0] [F 0]
   [win 8192] [cksum 0] [uptr 0] [opts #()]]

  (setv cksum-proto IPProto.TCP
        cksum-offset 16)

  (defn post-build [self]
    (#super post-build)
    (when (= self.dataofs 0)
      (setv self.dataofs (// (len self.head) 4)
            self.head (int-replace self.head 12 1 (+ (<< self.dataofs 4) self.res))))))
