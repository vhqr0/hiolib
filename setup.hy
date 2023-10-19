(setv
  version "0.1.0"
  requires ["hy~=0.27.0" "hyrule~=0.4.0"])

(require
  hyrule :readers * *)

(#/ setuptools.setup
  :name "hiolib"
  :version version
  :install-requires requires
  :author "vhqr"
  :description "IO library for hy"
  :packages (#/ setuptools.find-packages))
