open Mirage_types_lwt
open Lwt.Infix

let red fmt    = Printf.sprintf ("\027[31m"^^fmt^^"\027[m")
let green fmt  = Printf.sprintf ("\027[32m"^^fmt^^"\027[m")
let yellow fmt = Printf.sprintf ("\027[33m"^^fmt^^"\027[m")
let blue fmt   = Printf.sprintf ("\027[36m"^^fmt^^"\027[m")

let dhcid = match Dns.Rr_map.I.of_int 49 with Ok t -> t | Error _ -> assert false

let dhcid_k = Dns.Rr_map.(K (Unknown dhcid))

let dhc_prefix = "\x00B\x01" (* 16 bit type thingy, 8 bit digest *)

let gen_dhcid mac =
  dhc_prefix ^ Cstruct.to_string (Nocrypto.Hash.SHA256.hmac ~key:(Cstruct.of_string (Key_gen.hmac_secret ())) (Macaddr_cstruct.to_cstruct mac))

module Main (C: CONSOLE) (N: NETWORK) (PClock : Mirage_types.PCLOCK) (MClock : Mirage_types.MCLOCK) (Time: TIME) (R: RANDOM) = struct
  module ETH = Ethernet.Make(N)
  module ARP = Arp.Make(ETH)(Time)
  module IP = Static_ipv4.Make(R)(MClock)(ETH)(ARP)
  module ICMP = Icmpv4.Make(IP)
  module UDP = Udp.Make(IP)(R)
  module TCP = Tcp.Flow.Make(IP)(Time)(MClock)(R)
  module DC = Dhcp_config

  module Monitor = Monitoring_experiments.M.Pull(Time)(MClock)(TCP)

  let log c s =
    Astring.String.cuts ~sep:"\n" s |>
    Lwt_list.iter_s (fun line -> C.log c line)

  let of_interest dest net =
    Macaddr.compare dest (N.mac net) = 0 || not (Macaddr.is_unicast dest)

  let input_dhcp console net udp key config leases buf srcmac =
    match Dhcp_wire.pkt_of_buf buf (Cstruct.len buf) with
    | Error e ->
      log console (red "Can't parse packet: %s" e) >>= fun () ->
      Lwt.return leases
    | Ok pkt ->
      let now = MClock.elapsed_ns () |> Duration.to_sec |> Int32.of_int in
      match Dhcp_server.Input.input_pkt config leases pkt now with
      | Dhcp_server.Input.Silence -> Lwt.return leases
      | Dhcp_server.Input.Update leases ->
        log console (blue "Received packet %s - updated lease database" (Dhcp_wire.pkt_to_string pkt)) >>= fun () ->
        Lwt.return leases
      | Dhcp_server.Input.Warning w ->
        log console (yellow "%s" w) >>= fun () ->
        Lwt.return leases
      | Dhcp_server.Input.Error e ->
        log console (red "%s" e) >>= fun () ->
        Lwt.return leases
      | Dhcp_server.Input.Reply (reply, leases, binding) ->
        log console (blue "Received packet %s" (Dhcp_wire.pkt_to_string pkt)) >>= fun () ->
        N.write net ~size:(N.mtu net + Ethernet_wire.sizeof_ethernet) (Dhcp_wire.pkt_into_buf reply) >>= fun _ ->
        log console (blue "Sent reply packet %s" (Dhcp_wire.pkt_to_string reply)) >>= fun () ->
        (match key, binding with
         | None, _ | _, None -> Lwt.return_unit
         | Some (kname, key), Some (ip, name) ->
           let zone = DC.domain in
           let hostname =
             match name with
             | None -> None
             | Some name -> match Domain_name.prepend_label zone name with
               | Error (`Msg msg) ->
                 Logs.warn (fun m -> m "couldn't create hostname %s.%a: %s" name Domain_name.pp zone msg) ;
                 None
               | Ok name -> match Domain_name.host name with
                 | Error _ -> None
                 | Ok hostname ->
                   if Domain_name.Set.mem name DC.reserved_host_names then
                     None
                   else
                     Some hostname
           in
           let home =
             match hostname with
             | None -> None
             | Some hostname ->
               let zone = (zone, `K Dns.Rr_map.(K Soa))
               and update = [
                 Dns.Packet.Update.Remove Dns.Rr_map.(K A) ;
                 Dns.Packet.Update.Add Dns.Rr_map.(B (A, (3600l, Ipv4_set.singleton ip)))
               ]
               in
               Some (zone, (Domain_name.Map.empty, Domain_name.Map.singleton (Domain_name.raw hostname) update))
           and ptr =
             (* IP is 1.2.3.4 ; zone is 3.2.1.in-addr.arpa ; hostname 4.3.2.1.in-addr.arpa *)
             let hname = Ipaddr.V4.to_domain_name ip in
             let zname = Domain_name.drop_label_exn ~amount:1 hname in
             Logs.debug (fun m -> m "hname %a zname %a" Domain_name.pp hname
                            Domain_name.pp zname) ;
             let zone = (zname, `K Dns.Rr_map.(K Soa))
             and update =
               (match hostname with
                | None -> []
                | Some hostname ->
                  [
                    Dns.Packet.Update.Remove Dns.Rr_map.(K Ptr) ;
                    Dns.Packet.Update.Add Dns.Rr_map.(B (Ptr, (3600l, hostname))) ;
                  ]) @
               [
                 Dns.Packet.Update.Remove (dhcid_k);
                 Dns.Packet.Update.Add Dns.Rr_map.(B (Unknown dhcid, (Int32.of_int DC.max_lease_time, Txt_set.singleton (gen_dhcid srcmac))))
               ]
             in
             (zone, (Domain_name.Map.empty, Domain_name.Map.singleton (Domain_name.raw hname) update))
           in
           let now = Ptime.v (Pclock.now_d_ps ()) in
           let a = match home with
             | None -> None
             | Some (q, up) ->
               let header = Randomconv.int16 R.generate, Dns.Packet.Flags.empty in
               let packet = Dns.Packet.create header q (`Update up) in
               match Dns_tsig.encode_and_sign ~proto:`Udp packet now key kname with
               | Ok (data, _) -> Some data
               | Error _ -> None
           and b =
             let header = Randomconv.int16 R.generate, Dns.Packet.Flags.empty in
             let packet = Dns.Packet.create header (fst ptr) (`Update (snd ptr)) in
             match Dns_tsig.encode_and_sign ~proto:`Udp packet now key kname with
             | Ok (data, _) -> Some data
             | Error _ -> None
           in
           (match a with
            | None -> Lwt.return_unit
            | Some outa -> UDP.write ~dst:DC.dns_server ~dst_port:53 udp outa >>= function
              | Error e -> Logs.warn (fun m -> m "failed to send nsupdate %a" UDP.pp_error e) ; Lwt.return_unit
              | Ok () -> Lwt.return_unit) >>= fun () ->
           (match b with
            | None -> Lwt.return_unit
            | Some outa -> UDP.write ~dst:DC.dns_server ~dst_port:53 udp outa >>= function
              | Error e -> Logs.warn (fun m -> m "failed to send nsupdate %a" UDP.pp_error e) ; Lwt.return_unit
              | Ok () -> Lwt.return_unit)) >>= fun () ->
        Lwt.return leases

  let start c net _pclock clock _time _random _nocrypto =
    let transfer_key, update_key =
      List.fold_left (fun (t, u) key ->
          match Dns.Dnskey.name_key_of_string key with
          | Error _-> Logs.err (fun m -> m "failed to parse key %s" key) ; (t, u)
          | Ok (name, dnskey) ->
            match Domain_name.find_label name (String.equal "_transfer") with
            | Some _ ->
              Logs.debug (fun m -> m "found transfer key %a" Domain_name.pp name);
              (Some (name, dnskey), u)
            | None ->
              Logs.debug (fun m -> m "found update key %a" Domain_name.pp name);
              (t, Some (name, dnskey)))
        (None, None) (Key_gen.key ())
    in

    (* Get an ARP stack *)
    ETH.connect net >>= fun eth ->
    ARP.connect eth >>= fun arp ->
    ARP.add_ip arp DC.ip_address >>= fun () ->
    IP.connect ~ip:DC.ip_address ~network:DC.network clock eth arp >>= fun ip ->
    ICMP.connect ip >>= fun icmp ->
    UDP.connect ip >>= fun udp ->
    TCP.connect ip clock >>= fun tcp ->

    (* Build a dhcp server *)
    let config = Dhcp_server.Config.make
        ~hostname:(Domain_name.to_string DC.hostname)
        ~default_lease_time:DC.default_lease_time
        ~max_lease_time:DC.max_lease_time
        ~hosts:DC.hosts
        ~addr_tuple:(DC.ip_address, N.mac net)
        ~network:DC.network
        ~range:DC.range
        ~options:DC.options
    in
    let leases = ref (Dhcp_server.Lease.make_db ()) in
    Lwt.async (fun () ->
        (* handle DHCP messages special (need to capture full frame, ethernet
           headers are used by DHCP library) *)
        N.listen net ~header_size:Ethernet_wire.sizeof_ethernet (fun buf ->
            match Ethernet_packet.Unmarshal.of_cstruct buf with
            | Ok (ethif_header, _) when
                of_interest ethif_header.Ethernet_packet.destination net &&
                Dhcp_wire.is_dhcp buf (Cstruct.len buf) ->
              (* should we delay until DNS was ready for us? *)
              input_dhcp c net udp update_key config !leases buf ethif_header.Ethernet_packet.source >>= fun new_leases ->
              leases := new_leases;
              Lwt.return_unit
            | _ ->
              ETH.input
                ~arpv4:(ARP.input arp)
                ~ipv4:(IP.input
                         ~tcp:(TCP.input tcp ~listeners:(fun _ -> None))
                         ~udp:(UDP.input udp ~listeners:(fun ~dst_port:_ -> None))
                         ~default:(fun ~proto ~src ~dst buf ->
                             match proto with
                             | 1 -> ICMP.input icmp ~src ~dst buf
                             | _ -> Lwt.return_unit)
                         ip)
                ~ipv6:(fun _ -> Lwt.return_unit)
                eth buf
          ));

    (let ip = Key_gen.monitor () in
     TCP.create_connection tcp (ip, 8094) >|= function
     | Error e -> Logs.warn (fun m -> m "couldn't connect to resolver %a" TCP.pp_error e)
     | Ok flow -> Monitor.push ~hostname:"charrua.mirage" flow) >>= fun () ->

    (* if there's a DNS key, first ask the DNS server for AXFR of the reverse
       zone to fill in lease database from DHCID entries! *)
    begin match transfer_key with
      | None -> Lwt.return_unit
      | Some (keyname, key) ->
        let rev_zone = (* presume there's only one /24 *)
          Domain_name.drop_label_exn (Ipaddr.V4.to_domain_name DC.ip_address)
        in
        let dns =
          Dns.Packet.create (0xDEAD, Dns.Packet.Flags.empty)
            (rev_zone, `Axfr) `Axfr_request
        in
        TCP.create_connection tcp (DC.dns_server, 53) >>= function
        | Error e ->
          Logs.warn (fun m -> m "couldn't connect to resolver %a" TCP.pp_error e);
          Lwt.return_unit
        | Ok flow ->
          match
            Dns_tsig.encode_and_sign ~proto:`Tcp dns
              (Ptime.v (Pclock.now_d_ps ())) key keyname
          with
          | Error s ->
            Logs.warn (fun m -> m "couldn't sign dns request %a" Dns_tsig.pp_s s);
            Lwt.return_unit
          | Ok (buf, mac) ->
            Logs.debug (fun m -> m "created TCP connection to dns, writing");
            let out =
              let b = Cstruct.create 2 in
              Cstruct.BE.set_uint16 b 0 (Cstruct.len buf);
              Cstruct.append b buf
            in
            TCP.write flow out >>= function
            | Error we ->
              Logs.warn (fun m -> m "failed to write to resolver %a" TCP.pp_write_error we);
              Lwt.return_unit
            | Ok () ->
              let rec read_answer sofar =
                TCP.read flow >>= function
                | Error e ->
                  Logs.warn (fun m -> m "failed to read from resolver %a" TCP.pp_error e);
                  Lwt.return (Error ())
                | Ok `Eof ->
                  Logs.warn (fun m -> m "received EOF from resolver");
                  Lwt.return (Ok (Cstruct.shift sofar 2))
                | Ok `Data data ->
                  let data = Cstruct.append sofar data in
                  let len = Cstruct.BE.get_uint16 data 0 in
                  if Cstruct.len data = len + 2 then
                    Lwt.return (Ok (Cstruct.shift data 2))
                  else
                    read_answer data
              in
              read_answer Cstruct.empty >|= function
              | Error () -> ()
              | Ok data ->
                match
                  Dns_tsig.decode_and_verify (Ptime.v (Pclock.now_d_ps ()))
                    key keyname ~mac data
                with
                | Error e ->
                  Logs.warn (fun m -> m "couldn't verify dns reply %a" Dns_tsig.pp_e e)
                | Ok (pkt, _, _) ->
                  Logs.debug (fun m -> m "decoded and verify answer");
                  match Dns.Packet.reply_matches_request ~request:dns pkt with
                  | Error e ->
                    Logs.warn (fun m -> m "dns reply does not match request %a" Dns.Packet.pp_mismatch e)
                  | Ok `Axfr_reply (_, axfr) ->
                    (* axfr is a name_rr_map, we want a ip -> valid_until * hash *)
                    (* where: ip from domain_name, valid_until == now + ttl, hash = value of dhcid rr *)
                    Logs.debug (fun m -> m "axfr reply with %d" (Domain_name.Map.cardinal axfr));
                    let now = MClock.elapsed_ns () |> Duration.to_sec |> Int32.of_int in
                    let reserved_leases = Domain_name.Map.fold (fun k rr_map acc ->
                        match Dns.Rr_map.(find (Unknown dhcid) rr_map) with
                        | None -> acc
                        | Some (ttl, vals) ->
                          match Dns.Rr_map.Txt_set.fold (fun s acc ->
                              (* we're looking for our magic *)
                              if String.length s = 35 && Astring.String.is_prefix ~affix:dhc_prefix s then
                                Some s
                              else
                                acc) vals None
                          with
                          | None -> acc
                          | Some v ->
                            let valid_until = Int32.add now ttl in
                            match Ipaddr.V4.of_domain_name k with
                            | None -> acc
                            | Some ip -> (ip, valid_until, v) :: acc)
                        axfr []
                    in
                    Logs.debug (fun m -> m "%d reservations" (List.length reserved_leases));
                    (* we want both ip -> (valid_until, v) and v -> (valid_until, ip) databases *)
                    leases := Dhcp_server.Lease.add_reservations !leases gen_dhcid reserved_leases
                  | Ok _ ->
                    Logs.warn (fun m -> m "expected axfr reply")
    end >>= fun () ->
    fst (Lwt.task ())
end
