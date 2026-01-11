(require
  hpacket.inet.inet :readers * *)

(import
  hpacket.inet.inet *)

(defclass UDPPort [ProtoDict IntEnum]
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

  (setv disp-whitelist #("src" "dst")
        cksum-proto IPProto.UDP
        cksum-offset 6)

  (defn [property] parse-next-class [self]
    (or (.get UDPPort self.dst)
        (.get UDPPort self.src)))

  (defn pre-build [self]
    (#super pre-build)
    (when (= self.len 0)
      (setv self.len (+ 8 (len self.pload))))))
