(require
  hpacket.inet.inet :readers * *)

(import
  hpacket.inet.inet *
  hpacket.inet.udp *
  hpacket.inet.dns *)

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

(defpacket [(UDPPort.register UDPPort.DHCPv6Cli UDPPort.DHCPv6Cli)] DHCPv6 []
  [[int type :len 1 :to (normalize it DHCPv6MsgType)]]
  [[type DHCPv6MsgType.Solicit]]

  (defn [classmethod] parse-next-class [self]
    (if (in self.type #(DHCPv6MsgType.RelayForw DHCPv6MsgType.RelayRepl))
        DHCPv6RelayMsg
        DHCPv6Msg)))

(defpacket [] DHCPv6Msg [DispOptsMixin]
  [[int xid :len 3]
   [struct [opts] :struct (async-name DHCPv6OptListStruct)]]
  [[xid 0] [opts #()]]
  (setv disp-whitelist #("xid")))

(defpacket [] DHCPv6RelayMsg [DispOptsMixin]
  [[int hops :len 1]
   [struct [[linkaddr] [peeraddr]] :struct (async-name IPv6Addr) :repeat 2]
   [struct [opts] :struct (async-name DHCPv6OptListStruct)]]
  [[hops 0] [linkaddr IPv6-ZERO] [peeraddr IPv6-ZERO] [opts #()]]
  (setv disp-whitelist #("hops" "linkaddr" "peeraddr")))

(define-opt-dict DHCPv6Opt
  [ClientID     1
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
   NTPServer   56]
  [[int type :len 2 :to (normalize it DHCPv6Opt)]
   [varlen data
    :len 2
    :from (DHCPv6Opt.pack type it)
    :to (DHCPv6Opt.unpack type it)]])

(define-struct-opt DHCPv6Opt Status
  [[int code :len 2]
   [all msg]])

(define-int-opt DHCPv6Opt Pref 1)

(define-packet-opt DHCPv6Opt IANA [DispOptsMixin]
  [[int iaid :len 4]
   [int T1 :len 4]
   [int T2 :len 4]
   [struct [opts] :struct (async-name DHCPv6OptListStruct)]]
  [[iaid 0] [T1 0] [T2 0] [opts #()]]
  (setv disp-whitelist #("iaid" #("T1") #("T2"))))

(define-packet-opt DHCPv6Opt IATA [DispOptsMixin]
  [[int iaid :len 4]
   [struct [opts] :struct (async-name DHCPv6OptListStruct)]]
  [[iaid 0] [opts #()]]
  (setv disp-whitelist #("iaid")))

(define-packet-opt DHCPv6Opt IAPD [DispOptsMixin]
  [[int iaid :len 4]
   [int T1 :len 4]
   [int T2 :len 4]
   [struct [opts] :struct (async-name  DHCPv6OptListStruct)]]
  [[iaid 0] [T1 0] [T2 0] [opts #()]]
  (setv disp-whitelist #("iaid" #("T1") #("T2"))))

(define-packet-opt DHCPv6Opt IAAddr [DispOptsMixin]
  [[struct [addr] :struct (async-name IPv6Addr)]
   [int preftime :len 4]
   [int validtime :len 4]
   [struct [opts] :struct (async-name DHCPv6OptListStruct)]]
  [[addr IPv6-ZERO] [iaid 0] [preftime 0] [validtime 0] [opts #()]]
  (setv disp-whitelist #("addr" "iaid" #("preftime") #("validtime"))))

(define-packet-opt DHCPv6Opt IAPrefix [DispOptsMixin]
  [[int preftime :len 4]
   [int validtime :len 4]
   [int plen :len 1]
   [struct [prefix] :struct (async-name IPv6Addr)]
   [struct [opts] :struct (async-name DHCPv6OptListStruct)]]
  [[preftime 0] [validtime 0] [plen 64] [prefix IPv6-ZERO] [opts #()]]
  (setv disp-whitelist #(#("preftime") #("validtime") "plen" "prefix")))

(define-atom-struct-opt DHCPv6Opt ReqOpt
  [int opts
   :len 2
   :repeat-while (async-wait (.peek reader))
   :to-each (normalize it DHCPv6Opt)])

(define-int-opt DHCPv6Opt ElapsedTime 2)
(define-int-opt DHCPv6Opt RefreshTime 4)

(define-atom-struct-opt DHCPv6Opt DNSServer IPv6AddrList)
(define-atom-struct-opt DHCPv6Opt DNSSearch DNSNameList)
(define-atom-struct-opt DHCPv6Opt NTPServer IPv6AddrList)
