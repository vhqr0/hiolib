(require
  hiolib.rule :readers * *)

(import
  unittest [TestCase]
  random [randbytes getrandbits]
  socket
  scapy.all :as sp
  hpacket.inet :as hi)

(setv ip-src (socket.inet-ntop socket.AF-INET (randbytes 4))
      ip-dst (socket.inet-ntop socket.AF-INET (randbytes 4)))

(defclass TestIPv4 [TestCase]
  (defn test-build [self]
    (let [tos   (getrandbits 8)
          ipid  (getrandbits 8)
          ttl   (getrandbits 8)
          id    (getrandbits 8)
          seq   (getrandbits 8)
          data  (randbytes 32)]
      (setv hipkt (/ (hi.IPv4 :tos tos :id ipid :ttl ttl :src ip-src :dst ip-dst)
                     (hi.ICMPv4)
                     (hi.ICMPv4EchoReq :id id :seq seq)
                     data))
      (setv sppkt (sp.IP (bytes hipkt)))
      (setv ip (get sppkt 0))
      (.assertIsInstance self ip sp.IP)
      (.assertEqual self ip.tos tos)
      (.assertEqual self ip.id ipid)
      (.assertEqual self ip.ttl ttl)
      (setv icmp (get sppkt 1))
      (.assertIsInstance self icmp sp.ICMP)
      (.assertEqual self icmp.type 8)
      (.assertEqual self icmp.id id)
      (.assertEqual self icmp.seq seq)
      (.assertEqual self (bytes (get sppkt 2)) data)))

  (defn test-parse [self]
    (let [tos   (getrandbits 8)
          ipid  (getrandbits 8)
          ttl   (getrandbits 8)
          id    (getrandbits 8)
          seq   (getrandbits 8)
          data  (randbytes 32)]
      (setv sppkt (/ (sp.IP :tos tos :id ipid :ttl ttl :src ip-src :dst ip-dst)
                     (sp.ICMP :type 8 :id id :seq seq)
                     data))
      (setv hipkt (hi.IPv4.parse (bytes sppkt)))
      (setv ip (get hipkt 0))
      (.assertIsInstance self ip hi.IPv4)
      (.assertEqual self ip.tos tos)
      (.assertEqual self ip.id ipid)
      (.assertEqual self ip.ttl ttl)
      (setv icmp (get hipkt 2))
      (.assertIsInstance self icmp hi.ICMPv4EchoReq)
      (.assertEqual self icmp.id id)
      (.assertEqual self icmp.seq seq)
      (.assertEqual self (bytes (get hipkt 3)) data))))

(defclass TestICMPv4 [TestCase]
  (defn test-build [self]
    (setv hipkt (/ (hi.IPv4) (hi.ICMPv4) (hi.ICMPv4ParamProblem :ptr 3)
                   (hi.IPv4Error :src ip-src :dst ip-dst)))
    (setv sppkt (sp.IP (bytes hipkt)))
    (setv icmp (get sppkt 1))
    (.assertEqual self icmp.type 12)
    (.assertEqual self icmp.ptr 3)
    (setv iperror (get sppkt 2))
    (.assertEqual self iperror.src ip-src)
    (.assertEqual self iperror.dst ip-dst))

  (defn test-parse [self]
    (setv sppkt (/ (sp.IP) (sp.ICMP :type 12 :ptr 3) (sp.IPerror :src ip-src :dst ip-dst)))
    (setv hipkt (hi.IPv4.parse (bytes sppkt)))
    (setv icmp (get hipkt 2))
    (.assertIsInstance self icmp hi.ICMPv4ParamProblem)
    (.assertEqual self icmp.ptr 3)
    (setv iperror (get hipkt 3))
    (.assertIsInstance self iperror hi.IPv4Error)
    (.assertEqual self iperror.src ip-src)
    (.assertEqual self iperror.dst ip-dst)))

(export
  :objects [TestIPv4 TestICMPv4])
