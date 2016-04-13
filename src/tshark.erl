%%%-------------------------------------------------------------------
%%% @author João Domingues Loic Haas Rick Wertenbroek
%%% @doc
%%%
%%% @end
%%%-------------------------------------------------------------------

-module(tshark).

%% Other type not supported
-define(LINKTYPE_NULL, 0).

%% Other not supported
-define(PF_INET, 2).

% IP v4 specific
-define(IPv4_ID, 4).
-define(IPv4_MIN_HDR_LEN, 5).
-define(ICMP_PROTOCOL, 1).

-record(pcapHeader, {magicNumber, versionMajor, versionMinor, thisZone, sigfigs, snapLength, network}).
-record(packetHeader, {sec, uSec, savedLength, realLength}).
-record(ipV4Header, {tos, length, id, flags, fragmentOffset, ttl, protocol, protocolText, src, dest, options, payload}).
-record(icmpHeader, {type, text, code, crc, payload}).


-export([tshark_from_file/1, tshark_from_file_verbose/1, open_file/1, test/1]).
%% Helper functions to be tested
-ifdef(TEST).
-export([
	 ip_sub_protocol_from_int/1,
	 icmp_type_from_int/1,
	 string_ttl/1,
	 string_id/1]).
-endif.

get_seq_from_ipv4header(_) -> "seq=0/0".

ipv4_packet_to_string(Packet) ->
  <<Src0:8/big, Src1:8/big, Src2:8/big, Src3:8/big >> = Packet#ipV4Header.src,
  <<Dst0:8/big, Dst1:8/big, Dst2:8/big, Dst3:8/big >> = Packet#ipV4Header.dest,
  Parser = case get_parser_from_ip_sub_protocol(Packet#ipV4Header.protocol) of
             {ok, P} -> P;
             _ -> fun(_) -> "ERROR" end
           end,
  SimpleText =
    case Parser(Packet#ipV4Header.payload) of
      {ok, icmp, IcmpHeader} -> IcmpHeader#icmpHeader.text;
      _ -> "UNKNOWN"
    end,
  io_lib:format("~p.~p.~p.~p -> ~p.~p.~p.~p    ~s ~p ~s ~s, ~s, ~s",
    [Src0, Src1, Src2, Src3,
      Dst0, Dst1, Dst2, Dst3,
      Packet#ipV4Header.protocolText,
      Packet#ipV4Header.length + 4,
      SimpleText,
      string_id(Packet#ipV4Header.id),
      get_seq_from_ipv4header(Packet),
      string_ttl(Packet#ipV4Header.ttl)]).

packet_to_string(Parser, Header, Payload) ->
  %io:format("~p~n~p~n", [Header, Payload]),
  case Parser(Payload) of
    {ok, {ipv4, IpPacket}} -> ipv4_packet_to_string(IpPacket);
    _ -> "Error"
  end.


%% API
tshark_from_file(FileName) ->
  {ok, File} = open_file(FileName),
  {ok, PcapHeader} = extract_pcap_header(File),
  LazyReader = packet_reader(File),
  {ok, Parser} = get_link_type_parser(PcapHeader#pcapHeader.network),
  {_, _, Str} = lazy:foldl(
    fun(Packet, {N, LastHeader, Acc}) ->

      %
      {CurrentHeader, Str} =
        case Packet of
          {ok, Header, Payload} -> {Header, packet_to_string(Parser, Header, Payload)};
          _ -> {LastHeader, "Error"}
        end,

      %
      Sec =
        case LastHeader of
          first -> 0.0;
          LastHeader ->
            LastTime = LastHeader#packetHeader.sec * 1000000 + LastHeader#packetHeader.uSec,
            Time     = CurrentHeader#packetHeader.sec * 1000000 + CurrentHeader#packetHeader.uSec,
            (Time - LastTime) / 1000000.0
        end,

      % LOLLOL
      {N + 1, CurrentHeader,io_lib:format("~s  ~p   ~s    ~s~n", [
        Acc,
        N,
        float_to_list(Sec, [{decimals, 6}]),
        Str
      ])}
    end,
    {0, first,""}, LazyReader),
    io:format("~s~n", [Str]),
    {ok, Str}
.

tshark_from_file_verbose(FileName) ->
    {ok, FileName ++ ": rien pour le moment"}.

open_file(FileName) ->
  file:open(FileName, [read, binary, raw]).

read_all([lazy_end | _], _, _) -> ok;
read_all([{ok, Header, Payload} | T], Parser, Acc) ->
  io:format("Packet ~p~n", [Acc]),
  io:format("    Header : ~p~n", [Header]),
  io:format("    Payload : ~p~n", [Payload]),
  Packet = Parser(Payload),
  io:format("    Packet : ~p~n", [Packet]),
  read_all(T(), Parser, Acc + 1).

test(FileName) ->
  {ok, File} = open_file(FileName),
  {ok, PcapHeader} = extract_pcap_header(File),
  io:format("PcapHeader ~p~n", [PcapHeader]),
  Reader = packet_reader(File),
  {ok, Parser} = get_link_type_parser(PcapHeader#pcapHeader.network),
  read_all(Reader, Parser, 0).
%% Internals

read_length(File, Length) ->
  case file:read(File, Length) of
    {ok, Data} -> Data;
    {error, Any} -> {error, Any};
    eof -> {error, eof}
  end.

%% Maybe check if some things need to be little endian.
extract_pcap_header(File) ->
  MagicNumber = 16#a1b2c3d4,
  case read_length(File, 4 + 2 + 2 + 4 + 4 + 4 + 4) of
    <<MagicNumber:32/native, VersionMajor:16, VersionMinor:16,
      ThisZone:32, Sigfigs:32, Snaplen:32, Network:32>> ->
      Header = #pcapHeader{magicNumber = MagicNumber, versionMajor = VersionMajor,
        versionMinor = VersionMinor, thisZone = ThisZone, sigfigs = Sigfigs,
        snapLength = Snaplen, network = Network},
      {ok, Header};
    {error, Any} -> {error, {bad_header, Any}}
  end.

extract_packet_header(File) ->
  case read_length(File, 4 + 4 + 4 + 4) of
    <<TsSec:32/little, TsUsec:32/little, InclLen:32/little, OrigLen:32/little>> ->
      Header = #packetHeader{sec = TsSec, uSec = TsUsec, savedLength = InclLen, realLength = OrigLen},
      {ok, Header};
    {error, eof} -> {error, eof};
    Any -> {error, {bad_header, Any}}
  end.

% Warning payload can be error
read_packet(File) ->
  case extract_packet_header(File) of
    {ok, Header} ->
      Payload = read_length(File, Header#packetHeader.savedLength),
      {ok, Header, Payload};
    {error, eof} -> lazy_end;
    {error, Any} -> {error, Any}
  end.

packet_reader(File) -> [read_packet(File) | fun() -> packet_reader(File) end ].

ip_parser(Payload) ->
  case Payload of
    <<?IPv4_ID:4, IHL:4, TOS:8/big, Length:16/big,
        Identification:16/big, Flags:3, FragOffset:13/big,
        TTL:8, Protocol:8, _:16,
        SourceIP:4/binary,
        DestinationIP:4/binary,
        Rest/binary>> when IHL >= ?IPv4_MIN_HDR_LEN ->
      OptionLen = (IHL - ?IPv4_MIN_HDR_LEN) * 4,
      PayloadLen = (Length - (IHL * 4)),
      %io:format("IHL ~p, Length ~p, OptionLen ~p, PayloadLen ~p RestLen ~p~nRest :~p~n", [IHL, Length, OptionLen, PayloadLen, byte_size(Rest), Rest]),
      <<Options:OptionLen/binary, RestPayload:PayloadLen/binary>> = Rest,
      IpPacket = #ipV4Header{tos = TOS, length = Length, id = Identification, flags = Flags,
        fragmentOffset = FragOffset, ttl = TTL, protocol = Protocol,
        protocolText = ip_sub_protocol_from_int(Protocol),
        src = SourceIP, dest = DestinationIP,
        options = Options, payload = RestPayload},
      {ok, {ipv4, IpPacket}};
    _ -> {error, paylod_parse}
end
.

link_type_null_parser(Payload) ->
  <<ProtocolFamily:32/native, Rest/binary>> = Payload,
  %io:format("~p~n", [ProtocolFamily]),
  try ProtocolFamily of
    ?PF_INET -> ip_parser(Rest);
    Any -> {error, {unsoported_pf, Any}}
  catch
    error:Any -> {error, Any}
  end
.
get_link_type_parser(NetWorkType) when NetWorkType =:= ?LINKTYPE_NULL ->
  {ok, fun(P) -> link_type_null_parser(P) end};
get_link_type_parser(_) ->
  {error, unsupported_link_type}.

%% Helper functions
ip_sub_protocol_from_int(Integer) ->
    case Integer of
	?ICMP_PROTOCOL ->
	    "ICMP";
	_ ->
	    "UNKNOWN"
    end.

get_parser_from_ip_sub_protocol(Protocol) ->
  case Protocol of
    ?ICMP_PROTOCOL -> {ok, fun(X) -> parse_icmp_header(X) end};
    _ -> {error, unknown_protocol}
  end
.

parse_icmp_header(Payload) ->
  %io:format("ICMP PAYLOAD : ~p ~n", [Payload]),
  case Payload of
    <<Type:8/big, Code:8/big, Crc:16/big, Data/binary>> ->
      Text = icmp_type_from_int(Type),
      {ok, icmp,
      #icmpHeader{type = Type, text = Text, code = Code, crc = Crc, payload = Data}};
    _ -> {error, parsing}
  end.
icmp_type_from_int(Integer) ->
    case Integer of
	0 ->
	    "Echo (ping) reply  ";
	8 ->
	    "Echo (ping) request";
	_ ->
	    "Other"
    end.

string_ttl(TTL) ->
    lists:flatten(io_lib:format("ttl=~p", [TTL])).

string_id(BE_id) ->
    lists:flatten(io_lib:format("id=0x~4.16.0b", [BE_id])).

%% End of Module.
