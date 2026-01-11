(require
  hiolib.rule :readers * *
  hiolib.struct *)

(import
  functools [cached-property]
  hiolib.stream *
  hiolib.struct *
  hpacket.inet [Ether])

(setv PCAP-LE-MAGIC b"\xd4\xc3\xb2\xa1"
      PCAP-BE-MAGIC b"\xa1\xb2\xc3\xd4")

(defstruct PcapMagic
  [[bytes order
    :len 4
    :to (ecase it
               PCAP-LE-MAGIC "little"
               PCAP-BE-MAGIC "big")
    :from (ecase it
                 "little" PCAP-LE-MAGIC
                 "big"    PCAP-BE-MAGIC)]])

(defstruct PcapLEHead
  [[int major    :len 2 :order "little"]
   [int minor    :len 2 :order "little"]
   [int res1     :len 4 :order "little"]
   [int res2     :len 4 :order "little"]
   [int snaplen  :len 4 :order "little"]
   [int linktype :len 4 :order "little"]])

(defstruct PcapBEHead
  [[int major    :len 2 :order "big"]
   [int minor    :len 2 :order "big"]
   [int res1     :len 4 :order "big"]
   [int res2     :len 4 :order "big"]
   [int snaplen  :len 4 :order "big"]
   [int linktype :len 4 :order "big"]])

(defstruct PcapLEPacket
  [[int sec     :len 4 :order "little"]
   [int msec    :len 4 :order "little"]
   [int caplen  :len 4 :order "little"]
   [int origlen :len 4 :order "little"]
   [bytes packet :len caplen]])

(defstruct PcapBEPacket
  [[int sec     :len 4 :order "big"]
   [int msec    :len 4 :order "big"]
   [int caplen  :len 4 :order "big"]
   [int origlen :len 4 :order "big"]
   [bytes packet :len caplen]])

(defclass Pcap []
  (defn #-- init [self stream]
    (setv self.stream stream))

  (defn [cached-property] head-struct [self]
    (ecase self.order
           "little" PcapLEHead
           "big"    PcapBEHead))

  (defn [cached-property] packet-struct [self]
    (ecase self.order
           "little" PcapLEPacket
           "big"    PcapBEPacket))

  (defn [classmethod] reader [cls f]
    (doto (cls (RawIOStream f))
          (.read-head)))

  (defn [classmethod] writer [cls f #* args #** kwargs]
    (doto (cls (RawIOStream f))
          (.write-head #* args #** kwargs)))

  (defn read-head [self]
    (setv self.order (get (.unpack-from-stream PcapMagic self.stream) 0))
    (dict (.zip self.head-struct (.unpack-from-stream self.head-struct self.stream))))

  (defn write-head [self [order "little"] [snaplen 65535] [linktype 1]]
    (setv self.order order)
    (.write self.stream (.pack PcapMagic "little"))
    (.write self.stream (.pack self.head-struct
                               :major    2
                               :minor    4
                               :res1     0
                               :res2     0
                               :snaplen  snaplen
                               :linktype linktype)))

  (defn read-packet [self]
    (let [#(sec msec _ _ packet) (.unpack-from-stream self.packet-struct self.stream)]
      #(packet sec msec)))

  (defn write-packet [self packet [sec 0] [msec 0]]
    (.write self.stream (.pack self.packet-struct
                               :sec     sec
                               :msec    msec
                               :caplen  (len packet)
                               :origlen (len packet)
                               :packet  packet)))

  (defn read-parsed-packet [self]
    (let [#(packet sec msec) (.read-packet self)]
      #((Ether.parse packet) sec msec)))

  (defn write-parsed-packet [self packet #* args #** kwargs]
    (.write-packet self (.build packet) #* args #** kwargs))

  (defn #-- iter [self]
    (while (.peek self.stream)
      (let [#(packet _ _) (.read-parsed-packet self)]
        (yield packet)))))

(export
  :objects [Pcap])
