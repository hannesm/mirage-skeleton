open Mirage

let key =
  let doc = Key.Arg.info ~doc:"nsupdate key (name:type:value)" ["key"] in
  Key.(create "key" Arg.(opt (list string) [] doc))

let hmac_secret =
  let doc = Key.Arg.info ~doc:"hmac secret" ["hmac-secret"] in
  Key.(create "hmac-secret" Arg.(opt string "1234" doc))

let monitor =
  let doc = Key.Arg.info ~doc:"monitor host IP" ["monitor"] in
  Key.(create "monitor" Arg.(opt ipv4_address Ipaddr.V4.localhost doc))

let main = foreign ~deps:[abstract nocrypto]
    ~keys:Key.([ abstract key ; abstract hmac_secret ; abstract monitor ])
    "Unikernel.Main"
    (console @-> network @-> pclock @-> mclock @-> time @-> random @-> job)

let () =
  let packages = [
    package ~min:"1.0.0" "charrua";
    package "charrua-server";
    package "arp-mirage";
    package "ethernet";
    package ~sublibs:[ "icmpv4" ; "ipv4" ; "tcp" ; "udp" ] "tcpip";
    package "dns";
    package "dns-tsig";
    package "macaddr-cstruct";
    package "monitoring-experiments";
  ]
  in
  register "dhcp" ~packages [
    main $ default_console $ default_network $ default_posix_clock $ default_monotonic_clock $ default_time $ default_random
  ]
