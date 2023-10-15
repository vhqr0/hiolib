(require
  hiolib.rule :readers * *
  hiolib.struct *)

(import
  hiolib.struct *)

(setv PCAP-LE-MAGIC b"\xd4\xc3\xb2\xa1"
      PCAP-BE-MAGIC b"\xa1\xb2\xc3\xd4")

(defstruct PcapHead
  [[bytes magic :len 4]
   [bytes major :len 2]
   [bytes minor :len 2]
   [bytes thiszone :len 4]
   [bytes sigfigs :len 4]
   [bytes snaplen :len 4]
   [bytes linktype :len 4]])

(defstruct PcapPacketHead
  [[bytes sec :len 4]
   [bytes msec :len 4]
   [bytes caplen :len 4]
   [bytes len :len 4]])

(defclass PcapIntCoder []
  (defn #-- init [self magic]
    (setv self.endian
          (ecase magic
                 PCAP-LE-MAGIC "little"
                 PCAP-BE-MAGIC "big")))

  (defn pack [self i ilen]
    (.to-bytes i ilen self.endian))

  (defn unpack [self b]
    (int.from-bytes b self.endian)))

(defclass PcapReader []
  (defn #-- init [self reader]
    (setv self.reader reader))

  (defn read-head [self]
    (setv self.head (.unpack-dict-from-stream PcapHead self.reader)
          self.int-coder (PcapIntCoder (get self.head "magic"))))

  (defn read-packet [self]
    (let [#(sec msec caplen len)
          (gfor i (.unpack-from-stream PcapPacketHead self.reader)
                (.unpack self.int-coder i))
          data (.read-exactly self.reader caplen)]
      #(sec msec (cut data len))))

  (defn read-packets [self]
    (while (.peek self.reader)
      (yield (.read-packet self))))

  (defn read-parsed-packets [self]
    (import hiolib.util.inet :as inet)
    (gfor packet (.read-packets self) (inet.Ether.parse (get packet -1)))))

(defclass PcapWriter []
  (defn #-- init [self writer [magic PCAP-LE-MAGIC]]
    (setv self.writer writer
          self.magic magic
          self.int-coder (PcapIntCoder magic)))

  (defn write-head [self [major 0x0200] [minor 0x0400] [thiszone 0] [sigfigs 0] [snaplen 65535] [linktype 1]]
    (.write self.writer (.pack PcapHead
                               :magic    self.magic
                               :major    (.pack self.int-coder major 2)
                               :minor    (.pack self.int-coder minor 2)
                               :thiszone (.pack self.int-coder thiszone 4)
                               :sigfigs  (.pack self.int-coder sigfigs 4)
                               :snaplen  (.pack self.int-coder snaplen 4)
                               :linktype (.pack self.int-coder linktype 4))))

  (defn write-packet [self packet [sec 0] [msec 0]]
    (.write self.writer (.pack PcapPacketHead
                               :sec    (.pack self.int-coder sec 4)
                               :msec   (.pack self.int-coder msec 4)
                               :caplen (.pack self.int-coder (len packet) 4)
                               :len    (.pack self.int-coder (len packet) 4)))
    (.write self.writer packet))

  (defn write-parsed-packet [self packet #* args]
    (.write-packet self (bytes packet) #* args)))
