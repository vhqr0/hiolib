(require
  hiolib.rule :readers * *
  hiolib.struct *
  hiolib.packet *
  hiolib.util.inet.inet *)

(import
  enum [IntEnum]
  hiolib.struct *
  hiolib.packet *
  hiolib.util.inet.inet *)

(defclass DNSType [OptDict IntEnum]
  (setv CNAME   5
        A       1
        AAAA   28
        PTR    12
        NS      2
        SOA     6
        MX     15
        TXT    16
        ANY   255))

;;; compatible with opt dict defined by define-opt-dict
(setv DNSTypeOpt DNSType)

(defclass DNSRcode [IntEnum]
  (setv NoError     0
        FormatError 1
        ServerError 2
        NameError   3
        NotImpl     4
        Refused     5))

(async-defclass DNSName [(async-name Struct)]
  (setv names #("name"))

  (defn [staticmethod] pack [name]
    (when (isinstance name str)
      (setv name (lfor subname (.split name ".") (.encode subname))))
    (let [buf b""]
      (for [subname name]
        (cond (isinstance subname int)
              (do
                (+= buf (int-pack (+ 0xc000 subname) 2))
                (break))
              (= subname b"")
              (do
                (+= buf b"\x00")
                (break))
              True
              (+= buf (int-pack (len subname) 1) subname)))
      buf))

  (async-defn [staticmethod] unpack-from-stream [reader]
    (let [subnames []]
      (while True
        (let [nlen (int-unpack (async-wait (.read-exactly reader 1)))]
          (cond (= (& nlen 0xc0) 0xc0)
                (do
                  (.append subnames (+ (<< (& nlen 0x3f) 8) (int-unpack (async-wait (.read-exactly reader 1)))))
                  (return #(subnames)))
                (= nlen 0)
                (do
                  (.append subnames b"")
                  (return #((.decode (.join b"." subnames)))))
                True
                (.append subnames (async-wait (.read-exactly reader nlen)))))))))

(define-dry-atom-struct DNSNames names (async-name DNSName))

(defstruct DNSQR
  [[struct [name] :struct (async-name DNSName)]
   [int type :len 2 :to (normalize it DNSType)]
   [int cls :len 2]])

(defstruct DNSRR
  [[struct [name type cls] :struct (async-name DNSQR)]
   [int ttl :len 4]
   [varlen data
    :len 2
    :from (DNSType.pack type it)
    :to (DNSType.unpack type it)]])

(defpacket [(UDPService.register UDPService.DNS UDPService.MDNS UDPService.LLMNR)] DNS []
  [[int id :len 2]
   [bits [qr op aa tc rd ra z rcode] :lens [1 4 1 1 1 1 3 4]]
   [int qdcount :len 2]
   [int ancount :len 2]
   [int nscount :len 2]
   [int arcount :len 2]
   [struct qd :struct DNSQR :repeat qdcount]
   [struct an :struct DNSRR :repeat ancount]
   [struct ns :struct DNSRR :repeat nscount]
   [struct ar :struct DNSRR :repeat arcount]]
  [[id 0] [qr 1] [op 0] [aa 0] [tc 0] [rd 0] [ra 0] [z 0] [rcode DNSRcode.NoError]
   [qdcount 0] [ancount 0] [nscount 0] [arcount 0]
   [qd #()] [an #()] [ns #()] [ar #()]]

  (defn pre-build [self]
    (#super pre-build)
    (when (= self.qdcount 0)
      (setv self.qdcount (len self.qd)))
    (when (= self.ancount 0)
      (setv self.ancount (len self.an)))
    (when (= self.nscount 0)
      (setv self.nscount (len self.ns)))
    (when (= self.arcount 0)
      (setv self.arcount (len self.ar)))))

(define-atom-struct-opt DNSType CNAME DNSName)
(define-atom-struct-opt DNSType A     IPv4Addr)
(define-atom-struct-opt DNSType AAAA  IPv6Addr)
(define-atom-struct-opt DNSType PTR   DNSName)
(define-atom-struct-opt DNSType NS    DNSName)

(define-packet-opt DNSType SOA
  [[struct [[mname] [rname]] :struct (async-name DNSName) :repeat 2]
   [int serial :len 4]
   [int refresh :len 4]
   [int retry :len 4]
   [int expire :len 4]
   [int minimum :len 4]]
  [[mname ""] [rname ""]
   [serial 0] [refresh 0] [retry 0] [expire 0] [minimum 0]])

(define-struct-opt DNSType MX
  [[int pref :len 2]
   [struct [name] :struct (async-name DNSName)]])
