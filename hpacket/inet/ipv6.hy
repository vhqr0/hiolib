(require
  hpacket.inet.inet :readers * *)

(import
  hpacket.inet.inet *)

(define-opt-dict IPv6Opt
  [Pad1 0 PadN 1]
  [[int type :len 1 :to (normalize it IPv6Opt)]
   [varlen data
    :len (if (= type 0) 0 1)
    :from (IPv6Opt.pack type it)
    :to (IPv6Opt.unpack type it)]])

(defn ipv6-pad-opts [opts]
  (let [mod (% (+ (len opts) 2) 8)]
    (cond (= mod 0)
          opts
          (= mod 7)
          (+ opts b"\x00")
          True
          (let [n (- 6 mod)]
            (+ opts b"\x01" (int-pack n 1) (bytes n))))))

(define-atom-struct-opt IPv6Opt PadN
  [all pad
   :from (bytes (- it 2))
   :to (+ (len it) 2)])

(defpacket [(EtherType.register EtherType.IPv6)] IPv6 [CksumPloadMixin ProtoDispatchMixin]
  [[bits [ver tc fl] :lens [4 8 20]]
   [int plen :len 2]
   [int nh :len 1 :to (normalize it IPProto)]
   [int hlim :len 1]
   [struct [[src] [dst]] :struct (async-name IPv6Addr) :repeat 2]]
  [[ver 6] [tc 0] [fl 0] [plen 0] [nh 0] [hlim 64] [src IPv6-ZERO] [dst IPv6-ZERO]]

  (setv disp-whitelist #(#("fl") "nh" "src" "dst")
        proto-attr "nh"
        proto-dict IPProto)

  (defn cksum-phead [self buf proto]
    (.pack IPv6CksumPhead self.src self.dst (len buf) proto))

  (defn pre-build [self]
    (#super pre-build)
    (when (= self.plen 0)
      (setv self.plen (len self.pload)))))

(defpacket [(IPProto.register IPProto.Frag)] IPv6Frag
  ;; other than the following exts, frag ext has no elen fields,
  ;; therefore it isn't inherit from ipv6 ext mixin.
  [CksumProxyPloadMixin ProtoDispatchMixin]
  [[int nh :len 1 :to (normalize it IPProto)]
   [int res1 :len 1]
   [bits [offset res2 M] :lens [13 2 1]]
   [int id :len 4]]
  [[nh 0] [res1 0] [offset 0] [res2 0] [M 0] [id 0]]

  (setv disp-whitelist #("nh" #("offset") #("M") #("id"))
        proto-attr "nh"
        proto-dict IPProto))

(defclass IPv6ExtMixin [CksumProxyPloadMixin ProtoDispatchMixin]
  (setv proto-attr "nh"
        proto-dict IPProto)

  (defn post-build [self]
    (#super post-build)
    (when (= self.elen 0)
      (setv self.elen (- (// (len self.head) 8) 1)
            self.head (int-replace self.head 1 1 self.elen)))))

(defpacket [] IPv6Opts [DispOptsMixin IPv6ExtMixin]
  [[int nh :len 1 :to (normalize it IPProto)]
   [int elen :len 1]
   [bytes opts
    :len (- (* 8 (+ elen 1)) 2)
    :from (ipv6-pad-opts (IPv6OptListStruct.pack it))
    :to (get (IPv6OptListStruct.unpack it) 0)]]
  [[nh 0] [elen 0] [opts #()]]

  (setv disp-whitelist #("nh")))

(defclass [(IPProto.register IPProto.HBHOpts)]  IPv6HBHOpts  [IPv6Opts])
(defclass [(IPProto.register IPProto.DestOpts)] IPv6DestOpts [IPv6Opts])
