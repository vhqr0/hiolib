(require
  hpacket.inet.inet :readers * *)

(import
  hpacket.inet.inet *
  hpacket.inet.ipv4 *)

(defclass IPv4Error [IPv4])

(defclass ICMPv4Type [ProtoDict IntEnum]
  (setv EchoReq       8
        EchoRep       0
        DestUnreach   3
        TimeExceeded 11
        ParamProblem 12
        Redirect      5))

(defpacket [(IPProto.register IPProto.ICMPv4)] ICMPv4 [ProtoDispatchMixin]
  [[int type :len 1 :to (normalize it ICMPv4Type)]
   [int code :len 1]
   [int cksum :len 2]]
  [[type 0] [code 0] [cksum 0]]

  (setv disp-whitelist #("type" #("code"))
        proto-attr "type"
        proto-dict ICMPv4Type)

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

(defclass ICMPv4WithPacketMixin [] (defn [property] parse-next-class [self] IPv4Error))

(defpacket [(ICMPv4Type.register ICMPv4Type.DestUnreach)] ICMPv4DestUnreach [ICMPv4WithPacketMixin]
  [[int unused :len 4]] 
  [[unused 0]]
  (setv disp-whitelist #()))

(defpacket [(ICMPv4Type.register ICMPv4Type.TimeExceeded)] ICMPv4TimeExceeded [ICMPv4WithPacketMixin]
  [[int unused :len 4]] 
  [[unused 0]] 
  (setv disp-whitelist #()))

(defpacket [(ICMPv4Type.register ICMPv4Type.ParamProblem)] ICMPv4ParamProblem [ICMPv4WithPacketMixin]
  [[int ptr :len 1]
   [int unused :len 3]] 
  [[ptr 0] [unused 0]]
  (setv disp-whitelist #(#("ptr"))))

(defpacket [(ICMPv4Type.register ICMPv4Type.Redirect)] ICMPv4Redirect [ICMPv4WithPacketMixin]
  [[struct [addr] :struct (async-name IPv4Addr)]]
  [[addr IPv4-ZERO]])
