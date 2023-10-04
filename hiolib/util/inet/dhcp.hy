(require
  hiolib.rule :readers * *
  hiolib.struct *
  hiolib.packet *)

(import
  enum [IntEnum]
  hiolib.struct *
  hiolib.packet *
  hiolib.util.inet.inet *
  hiolib.util.inet.dns *)

(setv DHCPv4-MAGIC b"\x63\x82\x53\x63")

(defclass DHCPv4Op [IntEnum]
  (setv Req 1 Rep 2))

(defclass DHCPv4MsgType [IntEnum]
  (setv Discover 1
        Offer    2
        Request  3
        Decline  4
        ACK      5
        NAK      6
        Release  7
        Inform   8))

(defstruct DHCPv4OptStruct
  [[int type :len 1]
   [int dlen :len (if (in type #(0 255)) 0 1)]
   [bytes data :len dlen]])

(defclass DHCPv4Opt [OptDict IntEnum]
  (setv Pad           0
        End         255
        MsgType      53
        ServerID     54
        ClientID     61
        HostName     12
        VendorClass  60
        VendorSpec   43
        ReqAddr      50
        ReqParam     55
        LeaseTime    51
        RenewalTime  58
        RebindTime   59
        SubnetMask    1
        Router        3
        DNSServer     6)

  (defn [classmethod] get-struct [cls]
    DHCPv4OptStruct)

  (defn [classmethod] get-opt [cls type dlen data]
    #(type data))

  (defn [classmethod] get-fields [cls type data]
    #(type (len data) data)))

(defstruct DHCPv4OptsStruct
  [[all opts
    :from (DHCPv4Opt.pack it)
    :to (DHCPv4Opt.unpack it)]])

(defpacket [(UDPService.register UDPService.DHCPv4Cli UDPService.DHCPv4Srv)] DHCPv4 []
  [[int op :len 1 :to (enumlize it DHCPv4Op)]
   [int htype :len 1]
   [int hlen :len 1]
   [int hops :len 1]
   [int xid :len 4]
   [int secs :len 2]
   [int flags :len 2]
   [struct [[ciaddr] [yiaddr] [siaddr] [giaddr]] :struct (async-name IPv4Addr) :repeat 4]
   [struct [chaddr] :struct (async-name MACAddr)]
   [bytes pad :len 10]
   [bytes sname :len 64]
   [bytes file :len 128]
   [bytes magic :len 4]
   [struct [opts] :struct (async-name DHCPv4OptsStruct)]]
  [[op DHCPv4Op.Req] [htype 1] [hlen 6] [hops 0] [xid 0] [secs 0] [flags 0]
   [ciaddr IPv4-ZERO] [yiaddr IPv4-ZERO] [siaddr IPv4-ZERO] [giaddr IPv4-ZERO]
   [chaddr MAC-ZERO] [pad (bytes 10)] [sname (bytes 64)] [file (bytes 128)]
   [magic DHCPv4-MAGIC] [opts #()]])

(defclass [(DHCPv4Opt.register DHCPv4Opt.MsgType)] DHCPv4OptMsgType [IntOpt]
  (setv ilen 1
        enum-class DHCPv4MsgType))

(defclass [(DHCPv4Opt.register DHCPv4Opt.ReqAddr)] DHCPv4OptReqAddr [SpliceStructOpt IPv4Addr])

(defstruct DHCPv4OptReqParamStruct
  [[int params
    :len 1
    :repeat-until (not (async-wait (.peek reader)))
    :to-each (enumlize it DHCPv4Opt)]])

(defclass [(DHCPv4Opt.register DHCPv4Opt.ReqParam)] DHCPv4OptReqParam [SpliceStructOpt DHCPv4OptReqParamStruct])

(defclass [(DHCPv4Opt.register DHCPv4Opt.LeaseTime)]   DHCPv4OptLeaseTime   [IntOpt] (setv ilen 4))
(defclass [(DHCPv4Opt.register DHCPv4Opt.RenewalTime)] DHCPv4OptRenewalTime [IntOpt] (setv ilen 4))
(defclass [(DHCPv4Opt.register DHCPv4Opt.RebindTime)]  DHCPv4OptRebindTime  [IntOpt] (setv ilen 4))

(defclass [(DHCPv4Opt.register DHCPv4Opt.SubnetMask)] DHCPv4OptSubnetMask [SpliceStructOpt IPv4Addr])
(defclass [(DHCPv4Opt.register DHCPv4Opt.Router)]     DHCPv4OptRouter     [SpliceStructOpt IPv4Addrs])
(defclass [(DHCPv4Opt.register DHCPv4Opt.DNSServer)]  DHCPv4OptDNSServer  [SpliceStructOpt IPv4Addrs])

(defclass DHCPv6MsgType [IntEnum]
  (setv Solicit    1
        Advertise  2
        Request    3
        Confirm    4
        Renew      5
        Rebind     6
        Reply      7
        Release    8
        Decline    9
        Reconf    10
        InfoReq   11
        RelayForw 12
        RelayRepl 13))

(defstruct DHCPv6OptStruct
  [[int type :len 2]
   [varlen data :len 2]])

(defclass DHCPv6Opt [OptDict IntEnum]
  (setv ClientID     1
        ServerID     2
        RelayMsg     9
        Status      13
        Pref         7
        VendorClass 16
        VendorSpec  17
        IANA         3
        IATA         4
        IAPD        25
        IAAddr       5
        IAPrefix    26
        RapidCommit 14
        ReqOpt       6
        ElapsedTime  8
        RefreshTime 32
        DNSServer   23
        DNSSearch   24
        NTPServer   56)

  (defn [classmethod] get-struct [cls]
    DHCPv6OptStruct)

  (defn [classmethod] get-opt [cls type data]
    #(type data))

  (defn [classmethod] get-fields [cls type data]
    #(type data)))

(defstruct DHCPv6OptsStruct
  [[all opts
    :from (DHCPv6Opt.pack it)
    :to (DHCPv6Opt.unpack it)]])

(defpacket [(UDPService.register UDPService.DHCPv6Cli UDPService.DHCPv6Cli)] DHCPv6 []
  [[int type :len 1 :to (enumlize it DHCPv6MsgType)]
   [int xid :len 3]
   [struct [opts] :struct (async-name DHCPv6OptsStruct)]]
  [[type DHCPv6MsgType.Solicit] [xid 0] [opts #()]])

(defstruct DHCPv6OptStatusStruct
  [[int code :len 1]
   [all msg]])

(defclass [(DHCPv6Opt.register DHCPv6Opt.Status)] DHCPv6OptStatus [StructOpt DHCPv6OptStatusStruct])

(defclass [(DHCPv6Opt.register DHCPv6Opt.Pref)] DHCPv6OptPref [IntOpt] (setv ilen 1))

(defpacket [(DHCPv6Opt.register DHCPv6Opt.IANA)] DHCPv6OptIANA [PacketOpt]
  [[int iaid :len 4]
   [int T1 :len 4]
   [int T2 :len 4]
   [struct [opts] :struct (async-name DHCPv6OptsStruct)]]
  [[iaid 0] [T1 0] [T2 0] [opts #()]])

(defpacket [(DHCPv6Opt.register DHCPv6Opt.IATA)] DHCPv6OptIATA [PacketOpt]
  [[int iaid :len 4]
   [struct [opts] :struct (async-name DHCPv6OptsStruct)]]
  [[iaid 0] [opts #()]])

(defpacket [(DHCPv6Opt.register DHCPv6Opt.IAPD)] DHCPv6OptIAPD [PacketOpt]
  [[int iaid :len 4]
   [int T1 :len 4]
   [int T2 :len 4]
   [struct [opts] :struct (async-name  DHCPv6OptsStruct)]]
  [[iaid 0] [T1 0] [T2 0] [opts #()]])

(defpacket [(DHCPv6Opt.register DHCPv6Opt.IAAddr)] DHCPv6OptIAAddr [PacketOpt]
  [[struct [addr] :struct (async-name IPv6Addr)]
   [int preftime :len 4]
   [int validtime :len 4]
   [struct [opts] :struct (async-name DHCPv6OptsStruct)]]
  [[iaid 0] [preftime 0] [validtime 0] [opts #()]])

(defpacket [(DHCPv6Opt.register DHCPv6Opt.IAPrefix)] DHCPv6OptIAPrefix [PacketOpt]
  [[int preftime :len 4]
   [int validtime :len 4]
   [int plen :len 1]
   [struct [prefix] :struct (async-name IPv6Addr)]
   [struct [opts] :struct (async-name DHCPv6OptsStruct)]]
  [[preftime 0] [validtime 0] [plen 64] [prefix IPv6-ZERO] [opts #()]])

(defstruct DHCPv6OptReqOptStruct
  [[int opts
    :len 2
    :repeat-until (not (async-wait (.peek reader)))
    :to-each (enumlize it DHCPv6Opt)]])

(defclass [(DHCPv6Opt.register DHCPv6Opt.ReqOpt)] DHCPv6OptReqOpt [SpliceStructOpt DHCPv6OptReqOptStruct])

(defclass [(DHCPv6Opt.register DHCPv6Opt.ElapsedTime)] DHCPv6OptElapsedTime [IntOpt] (setv ilen 2))
(defclass [(DHCPv6Opt.register DHCPv6Opt.RefreshTime)] DHCPv6OptRefreshTime [IntOpt] (setv ilen 4))

(defclass [(DHCPv6Opt.register DHCPv6Opt.DNSServer)] DHCPv6OptDNSServer [SpliceStructOpt IPv6Addrs])
(defclass [(DHCPv6Opt.register DHCPv6Opt.DNSSearch)] DHCPv6OptDNSSearch [SpliceStructOpt DNSNames])
(defclass [(DHCPv6Opt.register DHCPv6Opt.NTPServer)] DHCPv6OptNTPServer [SpliceStructOpt IPv6Addrs])
