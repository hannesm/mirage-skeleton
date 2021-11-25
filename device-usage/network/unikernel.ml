open Lwt.Infix

module Main (S: Mirage_stack.V4V6) = struct

  let start s =
    let port = Key_gen.port () in
    S.listen_tcp s ~port (fun flow ->
        let dst, dst_port = S.TCP.dst flow in
        Logs.info (fun f -> f "new tcp connection from IP %a on port %d"
                      Ipaddr.pp dst dst_port);
        S.TCP.read flow >>= function
        | Ok `Eof -> Logs.info (fun f -> f "Closing connection!"); Lwt.return_unit
        | Error e -> Logs.warn (fun f -> f "Error reading data from established connection: %a" S.TCP.pp_error e); Lwt.return_unit
        | Ok (`Data b) ->
          Logs.info (fun f -> f "read: %d bytes:\n%s" (Cstruct.length b) (Cstruct.to_string b));
          S.TCP.close flow
      );

    S.listen s

end
