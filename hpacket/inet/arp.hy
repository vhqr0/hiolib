(require
  hpacket.inet.inet :readers * *)

(import
  hpacket.inet.inet *)

(defclass ARPOp [IntEnum]
  (setv Req 1 Rep 2))

(defpacket [(EtherType.register EtherType.ARP)] ARP []
  [[int hwtype :len 2]
   [int prototype :len 2]
   [int hwlen :len 1]
   [int protolen :len 1]
   [int op :len 2 :to (normalize it ARPOp)]
   [struct [hwsrc] :struct (async-name MACAddr)]
   [struct [protosrc] :struct (async-name IPv4Addr)]
   [struct [hwdst] :struct (async-name MACAddr)]
   [struct [protodst] :struct (async-name IPv4Addr)]]
  [[hwtype 1] [prototype EtherType.IPv4] [hwlen 6] [protolen 4] [op ARPOp.Req]
   [hwsrc MAC-ZERO] [protosrc IPv4-ZERO] [hwdst MAC-ZERO] [protodst IPv4-ZERO]]

  (setv disp-whitelist #("op" "hwsrc" "protosrc" "hwdst" "protodst")))
