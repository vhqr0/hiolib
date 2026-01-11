(require
  hiolib.rule :readers * *)

(import
  unittest [TestCase]
  random [randbytes getrandbits]
  socket
  scapy.all :as sp
  hpacket.inet :as hi)

(setv ip-src (socket.inet-ntop socket.AF-INET6 (randbytes 16))
      ip-dst (socket.inet-ntop socket.AF-INET6 (randbytes 16)))

(defclass TestIPv6 [TestCase]
  (defn test-build [self]
    (let [tc    (getrandbits  8)
          fl    (getrandbits 20)
          hlim  (getrandbits  8)
          id    (getrandbits  8)
          seq   (getrandbits  8)
          data  (randbytes   32)]
      (setv hipkt (/ (hi.IPv6 :tc tc :fl fl :hlim hlim :src ip-src :dst ip-dst)
                     (hi.IPv6Frag)
                     (hi.IPv6DestOpts :opts [#(hi.IPv6Opt.Pad1 b"")
                                             #(hi.IPv6Opt.PadN 4)])
                     (hi.ICMPv6)
                     (hi.ICMPv6EchoReq :id id :seq seq)
                     data))
      (setv sppkt (sp.IPv6 (bytes hipkt)))
      (setv ip (get sppkt 0))
      (.assertIsInstance self ip sp.IPv6)
      (.assertEqual self ip.tc tc)
      (.assertEqual self ip.fl fl)
      (.assertEqual self ip.hlim hlim)
      (setv frag (get sppkt 1))
      (.assertIsInstance self frag sp.IPv6ExtHdrFragment)
      (setv dest (get sppkt 2))
      (.assertIsInstance self dest sp.IPv6ExtHdrDestOpt)
      (setv pad1 (get sppkt 3))
      (.assertIsInstance self pad1 sp.Pad1)
      (setv padn (get sppkt 4))
      (.assertIsInstance self padn sp.PadN)
      (.assertEqual self padn.optlen 2)
      (setv icmp (get sppkt sp.ICMPv6EchoRequest))
      (.assertEqual self icmp.id id)
      (.assertEqual self icmp.seq seq)
      (.assertEqual self (bytes icmp.data) data)))

  (defn test-parse [self]
    (let [tc    (getrandbits  8)
          fl    (getrandbits 20)
          hlim  (getrandbits  8)
          id    (getrandbits  8)
          seq   (getrandbits  8)
          data  (randbytes   32)]
      (setv sppkt (/ (sp.IPv6 :tc tc :fl fl :hlim hlim :src ip-src :dst ip-dst)
                     (sp.IPv6ExtHdrFragment)
                     (sp.IPv6ExtHdrDestOpt :options [(sp.Pad1) (sp.PadN :optlen 2)])
                     (sp.ICMPv6EchoRequest :id id :seq seq :data data)))
      (setv hipkt (hi.IPv6.parse (bytes sppkt)))
      (setv ip (get hipkt 0))
      (.assertIsInstance self ip hi.IPv6)
      (.assertEqual self ip.tc tc)
      (.assertEqual self ip.fl fl)
      (.assertEqual self ip.hlim hlim)
      (setv frag (get hipkt 1))
      (.assertIsInstance self frag hi.IPv6Frag)
      (setv dest (get hipkt 2))
      (.assertIsInstance self dest hi.IPv6DestOpts)
      (.assertEqual self (get dest.opts 0) #(hi.IPv6Opt.Pad1 b""))
      (.assertEqual self (get dest.opts 1) #(hi.IPv6Opt.PadN 4))
      (setv icmp (get hipkt 4))
      (.assertIsInstance self icmp hi.ICMPv6EchoReq)
      (.assertEqual self icmp.id id)
      (.assertEqual self icmp.seq seq)
      (.assertEqual self (bytes (get hipkt 5)) data))))

(defclass TestICMPv6 [TestCase]
  (defn test-build [self]
    (setv hipkt (/ (hi.IPv6) (hi.ICMPv6) (hi.ICMPv6ParamProblem :ptr 3)
                   (hi.IPv6Error :src ip-src :dst ip-dst)))
    (setv sppkt (sp.IPv6 (bytes hipkt)))
    (setv icmp (get sppkt 1))
    (.assertIsInstance self icmp sp.ICMPv6ParamProblem)
    (.assertEqual self icmp.ptr 3)
    (setv iperror (get sppkt 2))
    (.assertEqual self iperror.src ip-src)
    (.assertEqual self iperror.dst ip-dst))

  (defn test-parse [self]
    (setv sppkt (/ (sp.IPv6) (sp.ICMPv6ParamProblem :ptr 3) (sp.IPerror6 :src ip-src :dst ip-dst)))
    (setv hipkt (hi.IPv6.parse (bytes sppkt)))
    (setv icmp (get hipkt 2))
    (.assertIsInstance self icmp hi.ICMPv6ParamProblem)
    (.assertEqual self icmp.ptr 3)
    (setv iperror (get hipkt 3))
    (.assertIsInstance self iperror hi.IPv6Error)
    (.assertEqual self iperror.src ip-src)
    (.assertEqual self iperror.dst ip-dst)))

(export
  :objects [TestIPv6 TestICMPv6])
