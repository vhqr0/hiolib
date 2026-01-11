(require
  hpacket.inet.inet :readers * *)

(import
  hpacket.inet.inet *
  hpacket.inet.ipv6 *)

(defclass IPv6Error [IPv6])

(defclass ICMPv6Type [ProtoDict IntEnum]
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

(defpacket [(IPProto.register IPProto.ICMPv6)] ICMPv6 [CksumProxySelfMixin ProtoDispatchMixin]
  [[int type :len 1 :to (normalize it ICMPv6Type)]
   [int code :len 1]
   [int cksum :len 2]]
  [[type 0] [code 0] [cksum 0]]

  (setv disp-whitelist #("type" #("code"))
        proto-attr "type"
        proto-dict ICMPv6Type)

  (setv cksum-proto  IPProto.ICMPv6
        cksum-offset 2))

(defpacket [] ICMPv6Echo []
  [[int [id seq] :len 2 :repeat 2]]
  [[id 0] [seq 0]])

(defclass [(ICMPv6Type.register ICMPv6Type.EchoReq)] ICMPv6EchoReq [ICMPv6Echo])
(defclass [(ICMPv6Type.register ICMPv6Type.EchoRep)] ICMPv6EchoRep [ICMPv6Echo])

(defclass ICMPv6WithPacketMixin []
  (defn [property] parse-next-class [self] IPv6Error))

(defpacket [(ICMPv6Type.register ICMPv6Type.DestUnreach)]  ICMPv6DestUnreach  [ICMPv6WithPacketMixin]
  [[int unused :len 4]]
  [[unused 0]]
  (setv disp-whitelist #()))

(defpacket [(ICMPv6Type.register ICMPv6Type.PacketTooBig)] ICMPv6PacketTooBig [ICMPv6WithPacketMixin]
  [[int mtu :len 4]]
  [[mtu 1280]])

(defpacket [(ICMPv6Type.register ICMPv6Type.TimeExceeded)] ICMPv6TimeExceeded [ICMPv6WithPacketMixin]
  [[int unused :len 4]]
  [[unused 0]]
  (setv disp-whitelist #()))

(defpacket [(ICMPv6Type.register ICMPv6Type.ParamProblem)] ICMPv6ParamProblem [ICMPv6WithPacketMixin]
  [[int ptr :len 4]]
  [[ptr 0]]
  (setv disp-whitelist #(#("ptr"))))
