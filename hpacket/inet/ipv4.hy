(require
  hpacket.inet.inet :readers * *)

(import
  hpacket.inet.inet *)

(defn ipv4-pad-opts [opts]
  (let [mod (% (len opts) 4)]
    (if (= mod 0) opts (+ opts (bytes (- 4 mod))))))

(defpacket [(EtherType.register EtherType.IPv4)] IPv4
  ;; order is necessary: next class mixin should resolve proto first,
  ;; then cksum pload mixin can calculate phead.
  [DispOptsMixin CksumPloadMixin ProtoDispatchMixin]
  [[bits [ver ihl] :lens [4 4]]
   [int tos :len 1]
   [int tlen :len 2]
   [int id :len 2]
   [bits [res DF MF offset] :lens [1 1 1 13]]
   [int ttl :len 1]
   [int proto :len 1 :to (normalize it IPProto)]
   [int cksum :len 2]
   [struct [[src] [dst]] :struct (async-name IPv4Addr) :repeat 2]
   [bytes opts
    :len (* (- ihl 5) 4)
    :from (ipv4-pad-opts (.pack IPv4OptListStruct it))
    :to (get (.unpack IPv4OptListStruct it) 0)]]
  [[ver 4] [ihl 0] [tos 0] [tlen 0] [id 0]
   [res 0] [DF 0] [MF 0] [offset 0] [ttl 64]
   [proto 0] [cksum 0] [src IPv4-ZERO] [dst IPv4-ZERO] [opts #()]]

  (setv disp-whitelist #(#("id") #("DF") #("MF") #("offset") "proto" "src" "dst")
        proto-attr "proto"
        proto-dict IPProto)

  (defn cksum-phead [self buf proto]
    (.pack IPv4CksumPhead self.src self.dst (len buf) proto))

  (defn post-build [self]
    (#super post-build)
    (when (= self.ihl 0)
      (setv self.ihl (// (len self.head) 4)
            self.head (int-replace self.head 0 1 (+ (<< self.ver 4) self.ihl))))
    (when (= self.tlen 0)
      (setv self.tlen (+ (len self.head) (len self.pload))
            self.head (int-replace self.head 2 2 self.tlen)))
    (when (= self.cksum 0)
      (setv self.cksum (cksum self.head)
            self.head (int-replace self.head 10 2 self.cksum)))))

(define-opt-dict IPv4Opt
  [EOL 0 NOP 1]
  [[int type :len 1 :to (normalize it IPv4Opt)]
   [varlen data
    :len (if (in type #(0 1)) 0 1)
    :len-from (if (in type #(0 1)) 0 (+ it 2))
    :len-to (if (in type #(0 1)) 0 (- it 2))
    :from (IPv4Opt.pack type it)
    :to (IPv4Opt.unpack type it)]])
