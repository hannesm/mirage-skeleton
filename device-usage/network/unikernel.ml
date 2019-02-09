open Lwt.Infix

module MyNet (A : Mirage_stack_lwt.V4) = struct

  let stored_stack_handler : A.t option ref = ref None

  let listen port =
    match !stored_stack_handler with
    | None -> failwith "Uninitialized"
    | Some k ->
      A.listen_tcpv4 k ~port (fun flow ->
          let dst, dst_port = A.TCPV4.dst flow in
          Logs.info (fun f -> f "new tcp connection from IP %s on port %d"
                        (Ipaddr.V4.to_string dst) dst_port);
          A.TCPV4.read flow >>= function
          | Ok `Eof -> Logs.info (fun f -> f "Closing connection!"); Lwt.return_unit
          | Error e -> Logs.warn (fun f -> f "Error reading data from established connection: %a" A.TCPV4.pp_error e); Lwt.return_unit
          | Ok (`Data b) ->
            Logs.debug (fun f -> f "read: %d bytes:\n%s" (Cstruct.len b) (Cstruct.to_string b));
            A.TCPV4.close flow
        );
      A.listen k
end

module Main (S: Mirage_stack_lwt.V4) = struct

  module My = MyNet(S)

  let start (s : S.t) =
    My.stored_stack_handler := Some s; (* save in global variable *)
    let port = Key_gen.port () in
    My.listen port

end
