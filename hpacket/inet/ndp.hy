(require
  hpacket.inet.inet :readers * *)

(import
  hpacket.inet.inet *
  hpacket.inet.icmpv6 *)

(defpacket [(ICMPv6Type.register ICMPv6Type.NDRS)] ICMPv6NDRS [DispOptsMixin]
  [[int res :len 4]
   [struct [opts] :struct (async-name ICMPv6NDOptListStruct)]]
  [[res 0] [opts #()]]

  (setv disp-whitelist #()))

(defpacket [(ICMPv6Type.register ICMPv6Type.NDRA)] ICMPv6NDRA [DispOptsMixin]
  [[int hlim :len 1]
   [bits [M O res] :lens [1 1 6]]
   [int routerlifetime :len 2]
   [int reachabletime :len 4]
   [int retranstimer :len 4]
   [struct [opts] :struct (async-name ICMPv6NDOptListStruct)]]
  [[hlim 0] [M 0] [O 0] [res 0] [routerlifetime 1800]
   [reachabletime 0] [retranstimer 0] [opts #()]]

  (setv disp-whitelist #(#("hlim") #("M") #("O") #("routerlifetime") #("reachabletime") #("retranstimer"))))

(defpacket [(ICMPv6Type.register ICMPv6Type.NDNS)] ICMPv6NDNS [DispOptsMixin]
  [[int res :len 4]
   [struct [tgt] :struct (async-name IPv6Addr)]
   [struct [opts] :struct (async-name ICMPv6NDOptListStruct)]]
  [[res 0] [tgt IPv6-ZERO] [opts #()]]

  (setv disp-whitelist #("tgt")))

(defpacket [(ICMPv6Type.register ICMPv6Type.NDNA)] ICMPv6NDNA [DispOptsMixin]
  [[bits [R S O res] :lens [1 1 1 29]]
   [struct [tgt] :struct (async-name IPv6Addr)]
   [struct [opts] :struct (async-name ICMPv6NDOptListStruct)]]
  [[R 0] [S 0] [O 0] [res 0] [tgt IPv6-ZERO] [opts #()]]

  (setv disp-whitelist #(#("R") #("S") #("O") "tgt")))

(defpacket [(ICMPv6Type.register ICMPv6Type.NDRM)] ICMPv6NDRM [DispOptsMixin]
  [[int res :len 4]
   [struct [[tgt] [dst]] :struct (async-name IPv6Addr) :repeat 2]
   [struct [opts] :struct (async-name ICMPv6NDOptListStruct)]]
  [[res 0] [tgt IPv6-ZERO] [dst IPv6-ZERO] [opts #()]]

  (setv disp-whitelist #("tgt" "dst")))



(define-opt-dict ICMPv6NDOpt
  [SrcAddr 1
   DstAddr 2
   Prefix  3
   RMHead  4
   MTU     5]
  [[int type :len 1 :to (normalize it ICMPv6NDOpt)]
   [varlen data
    :len 1
    :len-from (// (+ it 2) 8)
    :len-to (- (* 8 it) 2)
    :from (ICMPv6NDOpt.pack type it)
    :to (ICMPv6NDOpt.unpack type it)]])

(define-atom-struct-opt ICMPv6NDOpt SrcAddr MACAddr)
(define-atom-struct-opt ICMPv6NDOpt DstAddr MACAddr)

(define-packet-opt ICMPv6NDOpt Prefix []
  [[int plen :len 1]
   [bits [L A res1] :lens [1 1 6]]
   [int validlifetime :len 4]
   [int preferredtime :len 4]
   [int res2 :len 4]
   [struct [prefix] :struct (async-name IPv6Addr)]]
  [[plen 64] [L 0] [A 0] [res1 0]
   [validlifetime 0xffffffff] [preferredtime 0xffffffff]
   [res2 0] [prefix IPv6-ZERO]]
  (setv disp-whitelist #(#("L") #("A") #("validlifetime") #("preferredtime") "prefix")))

(define-packet-opt ICMPv6NDOpt RMHead []
  [[int res :len 6]]
  [[res 0]]
  (setv disp-whitelist #())
  (defn [property] parse-next-class [self] IPv6Error))

(define-int-opt ICMPv6NDOpt MTU 6)
