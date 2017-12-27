open Lwt.Infix

(* Definition of MQTT Control Packet Type *)
type mqtt_pkt_type =
  Reserved1 | Connect | Connack | Publish | Puback | Pubrec | Pubrel | Pubcomp | Subscribe | Suback | Unsubscribe | Unsuback | Pingreq | Pingresp | Disconnect | Reserved2 | Invalid

type tables = {
  name: string;
  index: (int, Bytes.t) Hashtbl.t;
  rindex: (Bytes.t, int) Hashtbl.t;
  record: (Bytes.t, Bytes.t list) Hashtbl.t;
  empty: (int, int) Hashtbl.t; (* to manage which index number in an index hash table does not have its value *)
  ridxinfo: (Bytes.t, int list) Hashtbl.t;
  mutable max_index: int;
}

module Main (S: Mirage_types_lwt.STACKV4) (Clock: Mirage_types.MCLOCK) = struct
  type mqtt_session = {
    cid: bytes option;
    flow: S.TCPV4.flow;
    cs: bool;
    wflag: bool;
    wqos: bool;
    wretain: bool;
    wtopic: bytes option;
    wmessage: bytes option;
    keepalive: int64;
  }

  let mqtt_port = 1883

  let total = ref 0

  (* Lock *)
  (* TODO: need it? *)

  (* Hash tables *)
  let flow_tbl = Hashtbl.create 1 (* Key: TCP/IP flow, Value: Client ID *)
  let rflow_tbl = Hashtbl.create 1 (* Key: Client ID, Value TCP/IP flow *)
  let conn_tbl = Hashtbl.create 1 (* Key: Client ID, Value: in connection or not *)
  let session_tbl = Hashtbl.create 1 (* Key: Client ID, Value: session info. *)
  let atime_tbl = Hashtbl.create 1 (* Key: Client ID, Value: last access time(int64) *)
  let topic_tbl = {
    name = "topic";
    index = Hashtbl.create 1; (* Key: index number[int], Value: Client ID *)
    rindex = Hashtbl.create 1; (* Key: Client ID, Value: index number[int] *)
    record = Hashtbl.create 1; (* Key: topic, Value: list of Client IDs *)
    empty = Hashtbl.create 1; (* Key: 0[int], Value: empty index numbers *)
    ridxinfo = Hashtbl.create 1; (* Key: Client ID, Value: list of index numbers *)
    max_index = 0; (* Maximum number of the index used *)
  }
  let filter_tbl = {
    name = "filter";
    index = Hashtbl.create 1; (* Key: index number[int], Value: Client ID *)
    rindex = Hashtbl.create 1; (* Key: Client ID, Value: index number[int] *)
    record = Hashtbl.create 1; (* Key: topic, Value: list of Client IDs *)
    empty = Hashtbl.create 1; (* Key: 0[int], Value: empty index numbers *)
    ridxinfo = Hashtbl.create 1; (* Key: Client ID, Value: list of index numbers *)
    max_index = 0; (* Maximum number of the index used *)
  }
  let forwarding_tbl = {
    name = "forwarding";
    index = Hashtbl.create 1; (* Key: index number[int], Value: Client ID *)
    rindex = Hashtbl.create 1; (* Key: Client ID, Value: index number[int] *)
    record = Hashtbl.create 1; (* Key: topic, Value: list of Client IDs *)
    empty = Hashtbl.create 1; (* Key: 0[int], Value: empty index numbers *)
    ridxinfo = Hashtbl.create 1; (* Key: Client ID, Value: list of index numbers *)
    max_index = 0; (* Maximum number of the index used *)
  }

  (* Hashtbl processing *)
  let tblfind tbl elem =
    try
      let binding = Hashtbl.find tbl elem in
      Some binding
    with
    | Not_found -> None

  (* Update a hash table forcibly *)
  let register_cid flow cid session =
    let register_flow f c =
      Hashtbl.replace flow_tbl f c;
      Hashtbl.replace rflow_tbl c f;
      ()
    in
    let register_conn c =
      Hashtbl.replace conn_tbl c true; ()
    in
    let register_session c s =
      Hashtbl.replace session_tbl c s; ()
    in
    register_flow flow cid |> fun () ->
    register_conn cid |> fun () ->
    register_session cid session

  let unregister_cid flow cid =
    let unregister_flow f c =
      Hashtbl.remove flow_tbl f;
      Hashtbl.remove rflow_tbl c;
      ()
    in
    let unregister_conn c =
      Hashtbl.remove conn_tbl c;
      Hashtbl.remove atime_tbl c;
      ()
    in
    unregister_flow flow cid |> fun () ->
    unregister_conn cid

  (* Generate a list for topics and filters *)
  let rec get_topic_list buf ofs elist =
    let rec get_dlm_previous_offset buf ofs =
      match (Bytes.get buf ofs) with
      | '/' when (ofs >= 0) -> Some ofs
      | _ when (ofs > 0) -> get_dlm_previous_offset buf (ofs - 1)
      | _ when (ofs = 0) -> None
      | _ -> None
    in
    match (get_dlm_previous_offset buf ofs) with
    Some n -> begin
      let elem = Bytes.to_string (Bytes.sub buf (n + 1) (ofs - n)) in
      match n with
      | 0 -> ("/" :: elem :: elist)
      | n when (n = ofs) -> get_topic_list buf (n - 1) ("/" :: elist)
      | n when (n > 0) -> get_topic_list buf (n - 1) ("/" :: elem :: elist)
      | _ -> elist
    end
    | None -> (Bytes.to_string (Bytes.sub buf 0 (ofs + 1))) :: elist

  (* Pattern matching for a topic and a filter *)
  let rec topic_matching_main flist tlist =
    match flist with
    | "#" :: [] -> begin
      match tlist with
      | [] -> Error ()
      | _ :: _ -> Ok ()
    end
    | "#" :: _ -> Error ()
    | "+" :: [] -> begin
      match tlist with
      | _ :: [] -> Ok ()
      | _ :: _ -> Error ()
      | [] -> Ok ()
    end
    | "+" :: ftl -> begin
      match tlist with
      | _ :: [] -> Error ()
      | _ :: ttl -> topic_matching_main ftl ttl
      | [] -> Error ()
    end
    | "/" :: [] -> begin
      match tlist with
      | "/" :: [] -> Ok ()
      | "/" :: _ -> Error ()
      | _ :: _ -> Error ()
      | [] -> Error ()
    end
    | "/" :: "#" :: [] -> Ok ()
    | "/" :: "+" :: [] -> begin
      match tlist with
      | [] -> Ok ()
      | "/" :: [] -> Ok ()
      | "/" :: _ :: [] -> Ok ()
      | _ :: _ -> Error ()
    end
    | "/" :: ftl -> begin
      match tlist with
      | "/" :: ttl -> topic_matching_main ftl ttl
      | _ :: _ -> Error ()
      | [] -> Error ()
    end
    | fe :: [] -> begin
      match tlist with
      | te :: [] when (fe = te) -> Ok ()
      | _ :: _ -> Error ()
      | [] -> Error ()
    end
    | fe :: ftl -> begin
      match tlist with
      | te :: ttl when (fe = te) -> topic_matching_main ftl ttl
      | _ :: _ -> Error ()
      | [] -> Error ()
    end
    | [] -> Error ()

  (* Check if a topic can match a filter especially for the topic starting with $ *)
  let topic_matching flist tlist =
    try
      let f_first = List.hd flist in
      let t_first = List.hd tlist in
      match (Bytes.get (Bytes.of_string t_first) 0) with
      | '$' -> begin
        match f_first with
        | "#" | "+" -> Error ()
        | _ -> topic_matching_main flist tlist
      end
      | _ -> topic_matching_main flist tlist
    with
      | Failure _ -> Error ()

  let update_record_values t k v =
    match tblfind t k with
    | Some values -> begin
      if ((List.mem v values) = false) then begin
        Hashtbl.replace t k (v :: values);
        ()
      end
      else ()
    end
    | None -> begin
      Hashtbl.add t k [v];
      ()
    end

  (* tbl: tables to be updated, k: topic or filter, c: cid *)
  let update_tables tbl k c =
    let update_index_tables tbl k =
      let index =
        match tblfind tbl.empty 0 with
        | Some x -> begin
          Hashtbl.remove tbl.empty 0;
          x
        end
        | None -> begin
          let max_index = (Hashtbl.length tbl.index) + 1 in 
          tbl.max_index <- max_index;
          max_index
        end
      in
      Hashtbl.add tbl.index index k;
      Hashtbl.add tbl.rindex k index;
      index
    in
    if (Hashtbl.mem tbl.record k) then
      let values = Hashtbl.find tbl.record k in
      if ((List.mem c values) = false) then begin
        Hashtbl.replace tbl.record k (c :: values);
        ()
      end
      else ()
    else begin
      Hashtbl.add tbl.record k [c];
      update_index_tables tbl k |> fun index ->
      update_record_values tbl.ridxinfo c index
    end

  let update_tables_by_topic topic cid =
    update_tables topic_tbl topic cid

  let update_tables_by_filter filter cid =
    update_tables filter_tbl filter cid

  let update_tables_by_forwarding topic cid =
    update_tables forwarding_tbl topic cid

  let get_value_list tbl =
    let add_element k v l = v :: l in
    Hashtbl.fold add_element tbl []

  let add_cid_to_record t c =
    match tblfind forwarding_tbl.record t with
    | Some cidlist -> begin
      if (List.mem c cidlist) then ()
      else begin
        Hashtbl.replace forwarding_tbl.record t (c :: cidlist);
        ()
      end
    end
    | None -> ()

  let update_forwarding_tables_by_filter f t cid =
    match (topic_matching (get_topic_list f ((Bytes.length f) - 1) []) (get_topic_list t ((Bytes.length t) - 1) [])) with
    | Ok () -> begin
      let rec loop c topiclist =
        match topiclist with
        | [] -> ()
        | topic :: tl -> begin
          add_cid_to_record topic c |> fun () ->
          loop c tl
        end
      in
      update_tables_by_forwarding t cid |> fun () ->
      loop cid (get_value_list forwarding_tbl.index)
    end
    | Error () -> ()

  let add_filter f cid =
    let rec loop index =
      match tblfind topic_tbl.index index with
      | Some t when (index <= 0) -> update_forwarding_tables_by_filter f t cid |> fun () -> ()
      | Some t -> update_forwarding_tables_by_filter f t cid |> fun () -> loop (index - 1)
      | None when (index <= 0) -> ()
      | None -> loop (index - 1)
    in
    update_tables_by_filter f cid |> fun () ->
    loop (topic_tbl.max_index)

  let update_forwarding_tables_by_topic f t cid =
    match (topic_matching (get_topic_list f ((Bytes.length f) - 1) []) (get_topic_list t ((Bytes.length t) - 1) [])) with
    | Ok () -> begin
      update_tables_by_forwarding t cid |> fun () ->
      add_cid_to_record t cid
    end
    | Error () -> ()

  let add_topic topic t_cid =
    let update_forwarding_tables_by_tlist i f =
      match tblfind filter_tbl.record f with
      | Some filter_cids -> begin
        let rec add_all_cids = function
          | [] -> Some f
          | f_cid :: tl -> begin
            update_forwarding_tables_by_topic f topic f_cid |> fun () -> 
            add_all_cids tl
          end
        in
        add_all_cids filter_cids
      end
      | None -> begin
        Logs.warn (fun f -> f "No filters found in add_topic().");
        Some f
      end
    in
    update_tables_by_topic topic t_cid |> fun () ->
    Hashtbl.filter_map_inplace update_forwarding_tables_by_tlist filter_tbl.index;
    Lwt.return_unit

  let remove_cid cid cidlist =
    let check_cid c =
      if (c = cid) then false
      else true
    in
    match List.filter check_cid cidlist with
    | [] -> []
    | clist -> clist

  let remove_index t elem =
    match tblfind t.rindex elem with
    | Some index -> begin
      Hashtbl.remove t.index index;
      Hashtbl.remove t.rindex elem;
      Hashtbl.add t.empty 0 index;
      ()
    end
    | None -> ()

  let remove_cid_from_record t cid elem =
    match tblfind t.record elem with
    | Some cidlist -> begin
      remove_cid cid cidlist |> function
        | [] -> begin
          Hashtbl.remove t.record elem;
          remove_index t elem
        end
        | clist -> begin
          Hashtbl.replace t.record elem clist;
          ()
        end
    end
    | None -> ()

  let remove_cid_from_record_by_index t cid i =
    match tblfind t.index i with
    | Some elem -> remove_cid_from_record t cid elem
    | None -> begin
      Logs.warn (fun f -> f "Could not remove cid %s from %s_tbl.record." (Bytes.to_string cid) t.name);
      ()
    end

  let remove_cid_from_all_tables tbl cid =
    let rec loop = function
      | [] -> ()
      | idx :: tl -> begin
        remove_cid_from_record_by_index tbl cid idx |> fun () ->
        loop tl
      end
    in
    match (tblfind tbl.ridxinfo cid) with
    | Some indexes -> begin
      Hashtbl.remove tbl.ridxinfo cid;
      loop indexes
    end
    | None -> begin
      Logs.info (fun f -> f "Could not find index numbers in %s_tbl.ridxinfo: %s" tbl.name (Bytes.to_string cid));
      ()
    end

  let cleaning_session flow =
    let cid = tblfind flow_tbl flow in
    match cid with
    | Some cid_bytes -> begin
      let session = tblfind session_tbl cid_bytes in
      let unregister_session c = 
        Hashtbl.remove session_tbl c; ()
      in
      match session with
      | Some s -> begin
        if s.cs then begin
          remove_cid_from_all_tables topic_tbl cid_bytes |> fun () ->
          remove_cid_from_all_tables filter_tbl cid_bytes |> fun () ->
          remove_cid_from_all_tables forwarding_tbl cid_bytes |> fun () ->
          unregister_session cid_bytes |> fun () ->
          unregister_cid flow cid_bytes |> fun () ->
          ()
        end else
          unregister_cid flow cid_bytes |> fun () ->
          ()
      end
      | None -> ()
    end
    | None -> ()

  (* TCP write with error cheking functionality *)
  let write_and_check flow buf =
    match (tblfind flow_tbl flow) with
    | Some cid -> begin
      match (tblfind conn_tbl cid) with
      | Some _ -> begin
        S.TCPV4.write flow buf >|= Rresult.R.is_error >>= function
        | true -> begin
          let len = Cstruct.BE.get_uint16 buf 2 in
          Logs.err (fun f -> f "[ERROR] TCP write error found: Destination cid=%s, topic=%s" (Bytes.to_string cid) (Cstruct.to_string (Cstruct.sub buf 4 len)));
          Lwt.return_unit
        end
        | false -> Lwt.return_unit
      end
      | None -> Lwt.return_unit
    end
    | None -> Lwt.return_unit

  (* UTF-8 field parsing *)
  let get_utf8_field data offset =
    (* TODO: need a UTF-8 library? *)
    let length = (Cstruct.BE.get_uint16 data offset) in
    match length with
    | 0 -> (None, 0)
    | n -> 
      let field = Bytes.create length in
      Cstruct.blit_to_bytes data (offset + 2) field 0 length;
      Logs.debug (fun f -> f "UTF8 string: length=%d, offset=%d, %s" length offset (Bytes.to_string field));
      (Some field, length + 2)

  (* Get the Remaining length value *)
  let get_remaining_length data =
    let rec calc_length data n total base =
      let tmp = total + base * ((Cstruct.get_uint8 data n) land 0x7F) in
      match ((Cstruct.get_uint8 data n) land 0x80) with
      | 0 -> (tmp, (n + 1))
      | 128 -> calc_length data (n + 1) tmp (base * 0x80)
      (* TODO: fix me! *)
      | _ -> (0, 0)
    in
    calc_length data 1 0 1

  (* Set the Remaining length field *)
  let set_remaining_length len =
    let rec calc_len_field length len_field base =
      let tmp = len_field + base * (length mod 0x80) in
      let next = length / 128 in
      match next with
      | 0 -> tmp
      | _ -> calc_len_field next (tmp + 0x80) (base * 0x100)
    in
    calc_len_field len 0 1

  (* Identify which packet type the incoming control packet has *)
  let get_pkt_type fh =
    match (fh lsr 4) with
    | 0 -> Reserved1
    | 1 -> Connect
    | 2 -> Connack
    | 3 -> Publish
    | 4 -> Puback
    | 5 -> Pubrec
    | 6 -> Pubrel
    | 7 -> Pubcomp
    | 8 -> Subscribe
    | 9 -> Suback
    | 10 -> Unsubscribe
    | 11 -> Unsuback
    | 12 -> Pingreq
    | 13 -> Pingresp
    | 14 -> Disconnect
    | 15 -> Reserved2
    | _ -> Invalid

  (* Fixed header processing *)
  let check_fixed_header data =
    let fixed_header = (Cstruct.get_uint8 data 0) in
    let flags = (fixed_header land 0x0F) in
    let type_num = (fixed_header lsr 4) in
    let pkt_type = get_pkt_type fixed_header in
    let length, offset = get_remaining_length data in
    Logs.debug (fun f -> f "flags = %d, type_num = %d length = %d offset = %d" flags type_num length offset);
    (pkt_type, flags, length, offset)

  (* Variable header processing *)
  (* Packet identifier processing *)
  let get_packet_identifier data offset pkt_type =
    match pkt_type with
    | Connect | Connack | Pingreq | Pingresp | Disconnect -> (None, offset)
    | Puback | Pubrec | Pubrel | Pubcomp | Subscribe | Suback | Unsubscribe | Unsuback -> (Some (Cstruct.BE.get_uint16 data offset), offset + 2)
    (* TODO: fixe me!!!!! "offset" is wrong, it should be based on the QoS field *)
    | Publish -> if (offset > 0) then (Some (Cstruct.BE.get_uint16 data offset), offset + 2) else (None, offset)
    | _ -> (None, offset)

  (* CONNECT *)
  let do_connect flow data offset =
    let check_proto data offset =
      match (Cstruct.BE.get_uint16 data offset) with
      | 0x0004 -> begin
        let name = Bytes.create 4 in
        Cstruct.blit_to_bytes data (offset + 2) name 0 (Bytes.length name);
        match (Bytes.to_string name) with
        | "MQTT" -> begin
          Ok ()
        end
        | str -> begin
          Logs.err (fun f -> f "[CONNECT][ERROR] An invalid protocol name: %s" str);
          Error ()
        end
      end
      | _ -> begin
        Logs.err (fun f -> f "[CONNECT][ERROR] Invalid string length for the protocol name.");
        Error ()
      end
    in
    let check_proto_level data offset =
      match (Cstruct.get_uint8 data offset) with
      | 0x4 -> 
        Ok () 
      | ver ->
        Logs.err (fun f -> f "[CONNECT][ERROR] An invalid protocol version: 0x%x" ver);
        Error ()
    in
    let get_flags_and_payload flow data offset =
      let flags = (Cstruct.get_uint8 data offset) in
      let cs = if ((flags land 0x02) = 0x0) then false else true in
      let wflag = if ((flags land 0x04) = 0x0) then false else true in
      let wqos = if ((flags land 0x18) = 0x0) then false else true in
      let wretain = if ((flags land 0x20) = 0x0) then false else true in
      let pflag = if ((flags land 0x40) = 0x0) then false else true in
      let unflag = if ((flags land 0x80) = 0x0) then false else true in
      Logs.info (fun f -> f "[CONNECT] Flags: Clear session=%B, Will flag=%B, Will QoS=%B, Will Retain=%B, Password flag=%B, Username flag=%B" cs wflag wqos wretain pflag unflag);

      let keepalive =  Cstruct.BE.get_uint16 data (offset + 1) in
      Logs.info (fun f -> f "[CONNECT] Keep alive: %d [sec]" keepalive);

      let cid, cid_next_ofs = get_utf8_field data (offset + 3) in
      let wtopic, wtopic_next_ofs =
        if wflag then begin
          Logs.info (fun f -> f "[CONNECT] Will topic:");
          get_utf8_field data (offset + 3 + cid_next_ofs)
        end
        else (None, 0)
      in
      let wmessage, wmessage_next_ofs = 
        if wflag then begin
          Logs.info (fun f -> f "[CONNECT] Will message:");
          get_utf8_field data (offset + 3 + cid_next_ofs + wtopic_next_ofs)
        end
        else (None, 0)
      in
      let username, username_next_ofs = 
        if unflag then begin
          Logs.info (fun f -> f "[CONNECT] Username:");
          get_utf8_field data (offset + 3 + cid_next_ofs + wtopic_next_ofs + wmessage_next_ofs)
        end
        else (None, 0)
      in
      let passwd, passwd_next_ofs = 
        if pflag then begin
          Logs.info (fun f -> f "[CONNECT] Password:");
          get_utf8_field data (offset + 3 + cid_next_ofs + wtopic_next_ofs + wmessage_next_ofs + username_next_ofs)
        end
        else (None, 0)
      in

      (* TODO: need authentification scheme here *)
      let pass_check = Ok () in

      (* Create session information *)
      let session = {
        cid = cid; flow = flow; cs = cs; wflag = wflag; wqos = wqos; wretain = wretain; wtopic = wtopic; wmessage = wmessage; keepalive = (Int64.mul (Int64.of_int keepalive) 1000000000L);
      } in
      let cid_error, cid_found =
        match cid with
        | Some bytes -> begin
          if (Hashtbl.mem session_tbl bytes) then begin (* a previous session exists *)
            if (Hashtbl.mem conn_tbl bytes) then begin
              Logs.err (fun f -> f "[CONNECT][ERROR] duplicated connections from %s" (Bytes.to_string bytes));
              (Error (), true) (* the previous session is recognized as "connected" *)
            end
            else begin
              (*if wflag then add_topic wmessage; *)
              register_cid flow bytes session |> fun () ->
              (Ok (), true)
            end
          end
          else begin
            (*if wflag then add_topic wmessage; *)
            register_cid flow bytes session |> fun () ->
            (Ok (), false)
          end
        end
        | None -> (Error (), false)
      in
      (cid_error, cid_found, pass_check)
    in
    let send_connack flow cid_error cid_found plevel_result auth_result =
      let payload = Cstruct.create 4 in
      Cstruct.BE.set_uint16 payload 0 0x2002;
      if cid_found then Cstruct.set_uint8 payload 2 0x1;
      match cid_error with
      | Ok () -> begin
        match plevel_result with
        | Ok () -> begin
          match auth_result with
          | Ok () -> begin
            Cstruct.set_uint8 payload 3 0x0;
            write_and_check flow payload
          end
          | Error () -> begin
            Cstruct.set_uint8 payload 3 0x5;
            write_and_check flow payload >>= fun () ->
            S.TCPV4.close flow >>= fun () ->
            Logs.err (fun f -> f "[CONNECT][ERROR] TCP connection closed due to user authentification fail.");
            Lwt.return_unit
          end
        end
        | Error () -> begin
          Cstruct.set_uint8 payload 3 0x1;
          write_and_check flow payload >>= fun () ->
          S.TCPV4.close flow >>= fun () ->
          Logs.err (fun f -> f "[CONNECT][ERROR] TCP connection closed due to MQTT version mismatch.");
          Lwt.return_unit
        end
      end
      | Error () -> begin
        Cstruct.set_uint8 payload 3 0x2;
        write_and_check flow payload >>= fun () ->
        S.TCPV4.close flow >>= fun () ->
        Logs.err (fun f -> f "[CONNECT][ERROR] TCP connection closed due to an invalid client connection found.");
        Lwt.return_unit
      end
    in
    try
      check_proto data offset |> fun proto_result ->
      check_proto_level data (offset + 6) |> fun plevel_result ->
      get_flags_and_payload flow data (offset + 7) |> fun (cid_error, cid_found, auth_result) ->
      match proto_result with
      | Ok () -> send_connack flow cid_error cid_found plevel_result auth_result
      | Error () -> begin
        Logs.err (fun f -> f "[CONNECT][ERROR] Protocol name error found.");
        Lwt.return_unit
      end
    with
    | Invalid_argument _ -> 
      Logs.err (fun f -> f "[CONNECT][ERROR] Invalid packet, we will close this connection.");
      S.TCPV4.close flow

  (* DISCONNECT *)
  let do_disconnect flow =
    cleaning_session flow |> fun () ->
    Logs.info (fun f -> f "[DISCONNECT] This connection will be closed.");
    Lwt.return_unit

  (* PUBLISH *)
  (* TODO: Implement Retain, QoS and DUP features *)
  let do_publish flow flags data offset =
    let check_flags retain qos dup =
      if (retain || (qos != 0) || dup) then begin
        Logs.warn (fun f -> f "[PUBLISH][WARNING] Invalid flags, all the flags must be false or zero: RETAIN=%B QOS=%d DUP=%B" retain qos dup);
        Ok ()
      end
      else begin
        Ok ()
      end
    in
    let check_vhdr data offset ret =
      match ret with
      | Ok () -> begin
        let check_wildcard bytes =
          let str = Bytes.to_string bytes in
          if (String.contains str '*') then begin
            Logs.err (fun f -> f "[PUBLISH][ERROR] The topic has a character of '*'.");
            None
          end
          else begin
            if (String.contains str '#') then begin
              Logs.err (fun f -> f "[PUBLISH][ERROR] The topic has a character of '#'.");
              None 
            end
            else
              Some bytes
          end
        in
        let topic, topic_next_offset = get_utf8_field data offset in
        match topic with
        | Some bytes -> begin
          Logs.info (fun f -> f "[PUBLISH] Topic name = %s" (Bytes.to_string bytes));
          check_wildcard bytes
        end
        | None -> begin
          Logs.err (fun f -> f "[PUBLISH][ERROR] This packet does not have a topic name.");
          None
        end
        (* We ignore the Packet Identifier because we do not support the QoS level 1 and 2 currently *)
      end
      | Error () -> None
    in
    let send_publish data topic =
      (* We disable all the flags on a PUBLISH packet from a publisher, then forward it to subscribers *)
      Cstruct.set_uint8 data 0 0x30;
      match tblfind forwarding_tbl.record topic with 
      | Some dest_cids -> begin
        let topic_send cid =
          match tblfind rflow_tbl cid with
          | Some flow -> begin
            write_and_check flow data
          end
          | None -> begin
            (*Logs.err (fun f -> f "[PUBLISH][ERROR] No TCP connection with a client found for topic publishing.");*)
            Lwt.return_unit
          end
        in
        Lwt_list.iter_s topic_send dest_cids
      end
      | None -> 
        Logs.info (fun f -> f "[PUBLISH] No topics found: %s" (Bytes.to_string topic));
        Lwt.return_unit
    in
    (* We currently do not support Retain, QoS and DUP features *)
    let retain = if ((flags land 0x01) = 0x0) then false else true in
    let qos = ((flags land 0x06) lsr 1) in
    let dup = if ((flags land 0x08) = 0x0) then false else true in
    try
      check_flags retain qos dup |> fun flags_ret ->

      check_vhdr data offset flags_ret |> function
      | Some topic -> begin
        match tblfind flow_tbl flow with
        | Some cid -> begin
          add_topic topic cid >>= fun () ->
          send_publish data topic >>= fun () ->
          Lwt.return_unit
        end
        | None -> begin
          Logs.err (fun f -> f "[PUBLISH][ERROR] No flow defined.");
          Lwt.return_unit
        end
      end
      | None -> begin
        Lwt.return_unit
      end
    with
    | Invalid_argument _ -> 
      Logs.err (fun f -> f "[PUBLISH][ERROR] Invalid packet, we will close this connection.");
      Lwt.return_unit

  (* SUBSCRIBE packet *)
  let do_subscribe flow data offset remaining_length =
  try
    match Cstruct.get_uint8 data 0 with
    | 0x82 -> begin
      let rec register_flist data filter_base remaining filter_list =
        match remaining with
        | 0 -> filter_list
        | n when (n >= 3) -> begin
          let get_filter data filter_offset filter_len =
            let filter, filter_next_offset = get_utf8_field data filter_offset in
            match filter with
            | Some bytes -> begin
              Logs.info (fun f -> f "[SUBSCRIBE] filter_offset=%d filter_len=%d" filter_offset filter_len);
              let qos = Cstruct.get_uint8 data (filter_offset + filter_len + 2) in
              Logs.info (fun f -> f "[SUBSCRIBE] Topic name = %s, qos = 0x%x" (Bytes.to_string bytes) qos);
              if (qos != 0) then Logs.info (fun f -> f "[SUBSCRIBE][WARNING] The QoS level is not 0, but this control packet is treated as the QoS level is 0");
              (Some bytes)
            end
            | None -> begin
              Logs.err (fun f -> f "[SUBSCRIBE][ERROR] This packet does not have a filter name.");
              None
            end
          in
          let len = Cstruct.BE.get_uint16 data filter_base in
          Logs.info (fun f -> f "[SUBSCRIBE] len=0x%x remaining=%d" len remaining);
          let new_remaining = remaining - len - 3 in (* 3bytes = 2bytes for the length field and 1byte for the QoS flag *)
          if (new_remaining < 0) then begin
            Logs.warn (fun f -> f "[SUBSCRIBE][WARNING] Invalid Remaining Length. Ignore parsing the filters.");
            []
          end
          else begin
            get_filter data filter_base len |> function
            | Some filter -> begin
              (* TODO: start here, to add an argument for Bytes of cid *)
              match (tblfind flow_tbl flow) with
              | Some cid -> begin
                add_filter filter cid |> fun () ->
                register_flist data (filter_base + len + 3) new_remaining (filter :: filter_list)
              end
              | None -> begin
                Logs.err (fun f -> f "[SUBSCRIBE][ERROR] No Client ID in registering a filter.");
                []
              end
            end
            | None -> begin
              Logs.err (fun f -> f "[SUBSCRIBE][ERROR] An error found in registering a filter.");
              []
            end
          end
        end
        | n -> Logs.info (fun f -> f "[SUBSCRIBE] Remaining %d" n); []
      in (* end of lec rec get_filter *)
      let send_suback pid rc =
        (* Create a SUBACK packet and send it out *)
        let payload = Cstruct.create 5 in
        Cstruct.BE.set_uint16 payload 0 0x9003;
        Cstruct.BE.set_uint16 payload 2 pid;
        Cstruct.set_uint8 payload 4 rc;
        write_and_check flow payload
      in
      let pid = Cstruct.BE.get_uint16 data offset in
      Logs.info (fun f -> f "[SUBSCRIBE] pid=0x%x." pid);
      register_flist data (offset + 2) (remaining_length - 2) [] |> function (* +/-2bytes: Packet identification *)
      | [] -> begin send_suback pid 0x80 end
      | _ -> begin
        (*List.iter (fun x -> Logs.info (fun f -> f "[SUBSCRIBE] filter=%s" (Bytes.to_string x))) tlists;*)
        send_suback pid 0x0
      end
    end
    | _ -> begin
      Logs.err (fun f -> f "[SUBSCRIBE][ERROR] Wrong fixed header.");
      S.TCPV4.close flow >>= fun () ->
      Lwt.return_unit
    end
  with
  | Invalid_argument _ -> 
    Logs.err (fun f -> f "[SUBSCRIBE][ERROR] Invalid packet.");
    Lwt.return_unit

  (* UNSUBSCRIBE packet *)
  let do_unsubscribe flow data offset remaining_length =
  try
    match Cstruct.get_uint8 data 0 with
    | 0xa2 -> begin
      let rec unregister_flist data filter_base remaining =
        match remaining with
        | 0 -> Ok ()
        | n when (n >= 3) -> begin
          let get_filter data filter_offset filter_len =
            let filter, filter_next_offset = get_utf8_field data filter_offset in
            match filter with
            | Some bytes -> begin
              Logs.info (fun f -> f "[UNSUBSCRIBE] filter_offset=%d filter_len=%d" filter_offset filter_len);
              Logs.info (fun f -> f "[UNSUBSCRIBE] Topic name = %s" (Bytes.to_string bytes));
              (Some bytes)
            end
            | None -> begin
              Logs.err (fun f -> f "[UNSUBSCRIBE][ERROR] This packet does not have a filter name.");
              None
            end
          in
          let len = Cstruct.BE.get_uint16 data filter_base in
          Logs.err (fun f -> f "[UNSUBSCRIBE] len=0x%x remaining=%d" len remaining);
          let new_remaining = remaining - len - 2 in (* 2bytes for the length field *)
          if (new_remaining < 0) then begin
            Logs.warn (fun f -> f "[UNSUBSCRIBE][WARNING] Invalid Remaining Length. Ignore parsing the filters.");
            Error ()
          end
          else begin
            get_filter data filter_base len |> function
            | Some filter -> begin
              match (tblfind flow_tbl flow) with
              | Some cid -> begin
                remove_cid_from_record filter_tbl cid filter |> fun () ->
                unregister_flist data (filter_base + len + 2) new_remaining
              end
              | None -> begin
                Logs.err (fun f -> f "[UNSUBSCRIBE][ERROR] No Client ID found in registering a filter.");
                Error ()
              end
            end
            | None -> begin
              Logs.err (fun f -> f "[UNSUBSCRIBE][ERROR] An error found in registering a filter.");
              Error ()
            end
          end
        end
        | n -> Logs.info (fun f -> f "[UNSUBSCRIBE] Remaining %d" n); Error ()
      in (* end of lec rec get_filter *)
      let send_unsuback pid =
        (* Create a UNSUBACK packet and send it out *)
        let payload = Cstruct.create 4 in
        Cstruct.BE.set_uint16 payload 0 0xb002;
        Cstruct.BE.set_uint16 payload 2 pid;
        write_and_check flow payload
      in
      let pid = Cstruct.BE.get_uint16 data offset in
      Logs.info (fun f -> f "[UNSUBSCRIBE] pid=0x%x." pid);
      unregister_flist data (offset + 2) (remaining_length - 2) |> function (* +/-2bytes: Packet identification *)
      | Ok () -> send_unsuback pid
      | Error () ->
        (*List.iter (fun x -> Logs.info (fun f -> f "[UNSUBSCRIBE] filter=%s" (Bytes.to_string x))) tlists;*)
        Logs.err (fun f -> f "[UNSUBSCRIBE][ERROR] Could not unsubscribe the filter pid %d." pid);
        send_unsuback pid
    end
    | _ -> begin
      Logs.err (fun f -> f "[UNSUBSCRIBE][ERROR] Wrong fixed header.");
      S.TCPV4.close flow >>= fun () ->
      Lwt.return_unit
    end
  with
  | Invalid_argument _ -> 
    Logs.err (fun f -> f "[UNSUBSCRIBE][ERROR] Invalid packet, we will close this connection.");
    Lwt.return_unit

  (* PINGREQ packet *)
  let do_pingreq flow =
    (* Create a PINGRESP packet and send it out *)
    let payload = Cstruct.create 2 in
    Cstruct.set_uint8 payload 0 0xD0;
    write_and_check flow payload

  (* Classify a incoming packet *)
  let do_pkt_processing flow pkt_type flags data offset remaining_length clock =
    let t_now = Clock.elapsed_ns clock in
    let _pkt_type =
      match tblfind flow_tbl flow with
      | Some cid -> begin (* the flow has already been acknoledged *)
        match tblfind atime_tbl cid with
        | Some t_last -> begin (* the last access time is valid *)
          match tblfind session_tbl cid with
          | Some s -> begin
            (* TODO: to change the threshould for a keepalive value *)
            if ((Int64.compare (Int64.sub t_now t_last) s.keepalive) < 0) then begin
              Hashtbl.replace atime_tbl cid t_now;
              pkt_type
            end
            else begin
              Logs.info (fun f -> f "[KEEPALIVE][WARN] longer access interval than the keepalive value: cid=%s" (Bytes.to_string cid));
              pkt_type
            end
          end
          | None -> begin
            Hashtbl.replace atime_tbl cid t_now;
            pkt_type
          end
        end
        | None -> begin
          Hashtbl.replace atime_tbl cid t_now;
          pkt_type
        end
      end
      | None -> pkt_type
    in
    match _pkt_type with
    | Connect -> begin
      Logs.info (fun f -> f "Received a CONNECT packet.");
      do_connect flow data offset
    end
    | Disconnect -> begin
      Logs.info (fun f -> f "Received a DISCONNECT packet.");
      do_disconnect flow
    end
    | Publish -> begin
      Logs.info (fun f -> f "Received a PUBLISH packet.");
      do_publish flow flags data offset 
    end
    | Subscribe -> begin
      Logs.info (fun f -> f "Received a SUBSCRIBE packet.");
      do_subscribe flow data offset remaining_length
    end
    | Unsubscribe -> begin
      Logs.info (fun f -> f "Received an UNSUBSCRIBE packet.");
      do_unsubscribe flow data offset remaining_length
    end
    | Pingreq -> begin
      Logs.info (fun f -> f "Received a PINGREQ packet.");
      do_pingreq flow
    end
    | _ -> Lwt.return_unit

  (* For debugging *)
  let dump_tables () = 
    let get_all_cids () = get_value_list flow_tbl in
    let dump_flow () =
      let cids = get_all_cids () in
      let print_elems cid = 
        Printf.printf "(%s) " (Bytes.to_string cid); 
        ()
      in
      Printf.printf "===== flow information =====\n";
      Printf.printf "Client IDs: ";
      match cids with
      | [] -> begin
        Printf.printf "nothing\n";
        ()
      end
      | cl -> begin
        List.iter print_elems cl;
        Printf.printf "\n";
        ()
      end
    in
    let dump_conn () = 
      let cids = get_all_cids () in
      let print_elems tbl cid = 
        match tblfind tbl cid with
        | Some x -> begin
          Printf.printf "(%s, %B) " (Bytes.to_string cid) x; 
          ()
        end
        | None -> begin
          Printf.printf "(%s, Error) " (Bytes.to_string cid); 
          ()
        end
      in
      Printf.printf "===== Connection information =====\n";
      Printf.printf "(CID, status): ";
      match cids with
      | [] -> begin
        Printf.printf "nothing\n";
        ()
      end
      | cl -> begin
        List.iter (print_elems conn_tbl) cl;
        Printf.printf "\n";
        ()
      end
    in
    let dump_session () =
      let cids = get_all_cids () in
      let print_cs cid = 
        if Hashtbl.mem session_tbl cid then begin 
          match tblfind session_tbl cid with
          | Some s -> begin
            Printf.printf "(%s, %B) " (Bytes.to_string cid) s.cs;
            ()
          end
          | None -> begin
            Printf.printf "(%s, None) " (Bytes.to_string cid);
            ()
          end
        end
        else ()
      in
      Printf.printf "===== Session information =====\n";
      Printf.printf "(CID, cs): ";
      match cids with
      | [] -> begin
        Printf.printf "nothing\n";
        ()
      end
      | cl -> begin
        List.iter print_cs cl;
        Printf.printf "\n";
        ()
      end
    in
    let dump_record_all t =
      let dump_index () =
        let indexes = get_value_list t.rindex in
        let print_index tbl index = 
          Printf.printf "(%d, %s) " index (Bytes.to_string (Hashtbl.find tbl index)); 
          ()
        in
        Printf.printf "----- Index information -----\n";
        Printf.printf "(index, CID): ";
        match indexes with
        | [] -> begin
          Printf.printf "nothing\n";
          ()
        end
        | il -> begin
          List.iter (print_index t.index) il;
          Printf.printf "\n";
          ()
        end
      in
      let dump_rindex () =
        let elems = get_value_list t.index in
        let print_elem tbl elem = 
          Printf.printf "(%s, %d) " (Bytes.to_string elem) (Hashtbl.find tbl elem); 
          ()
        in
        Printf.printf "----- Reverse index information -----\n";
        Printf.printf "(CID, index): ";
        match elems with
        | [] -> begin
          Printf.printf "nothing\n";
          ()
        end
        | el -> begin
          List.iter (print_elem t.rindex) el;
          Printf.printf "\n";
          ()
        end
      in
      let dump_record () =
        let print_record elem = 
          let print_record_cids elem cid = 
            Printf.printf "(%s, %s) " (Bytes.to_string elem) (Bytes.to_string cid);
            ()
          in
          match (tblfind t.record elem) with
          | Some cids -> begin
            match cids with
            | [] -> begin
              Printf.printf "This element does not have elements: %s\n" (Bytes.to_string elem);
              ()
            end
            | cl -> begin
              Printf.printf "(elem, CID): ";
              List.iter (print_record_cids elem) cl;
              Printf.printf "\n";
              ()
            end
          end
          | None -> begin
            Printf.printf "This element is not registered: %s\n" (Bytes.to_string elem);
            ()
          end
        in
        let elems = get_value_list t.index in
        Printf.printf "----- Element information -----\n";
        List.iter print_record elems;
        ()
      in
      let dump_ridxinfo () =
        Printf.printf "----- record index information -----\n";
      in
      let dump_empty () =
        Printf.printf "----- Index empty information -----\n";
        match (Hashtbl.find_all t.empty 0) with
        | [] -> begin
          Printf.printf "nothing\n";
          ()
        end
        | il -> begin
          let print_elems index = 
            Printf.printf "(%d) " index; 
            ()
          in
          Printf.printf "Max_index: %d, (empty_index): " t.max_index;
          List.iter print_elems il;
          Printf.printf "\n";
          ()
        end
      in
      Printf.printf "===== Cache information (%s) =====\n" t.name;
      dump_index () |> fun () ->
      dump_rindex () |> fun () ->
      dump_record () |> fun () ->
      dump_empty ()
    in
    dump_flow () |> fun () ->
    dump_conn () |> fun () ->
    dump_session () |> fun () ->
    dump_record_all topic_tbl |> fun () ->
    dump_record_all filter_tbl |> fun () ->
    dump_record_all forwarding_tbl |> fun () ->
    Printf.printf "\n%!";
    ()

  (* Main function *)
  let mqtt_broker flow clock =
    let rec broker_body flow clock =
      S.TCPV4.read flow >|= Rresult.R.get_ok >>= function
      | `Eof ->
        cleaning_session flow |> fun () ->
        (*dump_tables () |> fun () -> *)
        S.TCPV4.close flow >>= fun () ->
        Lwt.return_unit
      | `Data data ->
        check_fixed_header data |> fun (pkt_type, flags, remaining_length, offset) ->
        do_pkt_processing flow pkt_type flags data offset remaining_length clock >>= fun () ->
        (*dump_tables () |> fun () ->*)
        broker_body flow clock
    in
    broker_body flow clock 

  let start s clock =
    let ips = List.map Ipaddr.V4.to_string (S.IPV4.get_ip (S.ipv4 s)) in
    (* debug is too much for us here *)
    Logs.set_level ~all:true (Some Logs.Warning);
    Logs.app (fun f -> f "MQTT broker process started:");
    Logs.app (fun f -> f "IP address: %s" (String.concat "," ips));
    Logs.app (fun f -> f "Port number: %d" mqtt_port);

    S.listen_tcpv4 s ~port:mqtt_port (fun flow ->
      mqtt_broker flow clock
    );
    S.listen s

end
