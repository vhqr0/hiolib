(require
  hpacket.inet.inet :readers * *)

(import
  hpacket.inet.inet *
  hpacket.inet.udp *
  hpacket.inet.dns *)


;;; dhcpv4

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

(defpacket [(UDPPort.register UDPPort.DHCPv4Cli UDPPort.DHCPv4Srv)] DHCPv4 [DispOptsMixin]
  [[int op :len 1 :to (normalize it DHCPv4Op)]
   [int htype :len 1]
   [int hlen :len 1]
   [int hops :len 1]
   [int xid :len 4]
   [int secs :len 2]
   [bits [B res] :lens [1 7]]
   [struct [[ciaddr] [yiaddr] [siaddr] [giaddr]] :struct (async-name IPv4Addr) :repeat 4]
   [struct [chaddr] :struct (async-name MACAddr)]
   [bytes pad :len 10]
   [bytes sname :len 64]
   [bytes file :len 128]
   [bytes magic :len 4]
   [struct [opts] :struct (async-name DHCPv4OptListStruct)]]
  [[op DHCPv4Op.Req] [htype 1] [hlen 6] [hops 0] [xid 0] [secs 0] [B 0] [res 0]
   [ciaddr IPv4-ZERO] [yiaddr IPv4-ZERO] [siaddr IPv4-ZERO] [giaddr IPv4-ZERO]
   [chaddr MAC-ZERO] [pad (bytes 10)] [sname (bytes 64)] [file (bytes 128)]
   [magic DHCPv4-MAGIC] [opts #()]]

  (setv disp-whitelist #("op" #("hops") "xid" #("B") "ciaddr" "yiaddr" "siaddr" "giaddr" "chaddr")))

(define-opt-dict DHCPv4Opt
  [Pad           0
   End         255
   MsgType      53
   ServerID     54
   ClientID     61
   HostName     12
   VendorClass  60
   VendorSpec   43
   ReqAddr      50
   ReqOpt       55
   LeaseTime    51
   RenewalTime  58
   RebindTime   59
   SubnetMask    1
   Router        3
   DNSServer     6]
  [[int type :len 1 :to (normalize it DHCPv4Opt)]
   [varlen data
    :len (if (in type #(0 255)) 0 1)
    :from (DHCPv4Opt.pack type it)
    :to (DHCPv4Opt.unpack type it)]])

(define-int-opt DHCPv4Opt MsgType 1 DHCPv4MsgType)

(define-atom-struct-opt DHCPv4Opt ReqAddr IPv4Addr)

(define-atom-struct-opt DHCPv4Opt ReqOpt
  [int opts
   :len 1
   :repeat-while (async-wait (.peek reader))
   :to-each (normalize it DHCPv4Opt)])

(define-int-opt DHCPv4Opt LeaseTime   4)
(define-int-opt DHCPv4Opt RenewalTime 4)
(define-int-opt DHCPv4Opt RebindTime  4)

(define-atom-struct-opt DHCPv4Opt SubnetMask IPv4Addr)
(define-atom-struct-opt DHCPv4Opt Router     IPv4AddrList)
(define-atom-struct-opt DHCPv4Opt DNSServer  IPv4AddrList)
