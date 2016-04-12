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

%% tshark: tshark library's entry point.

-export([open_file/1, test/1]).
%% API
tshark_from_file(FileName) ->
    .
thasrk_from_file_verbose(FileName) ->
    .

-record(pcapHeader, {magicNumber, versionMajor, versionMinor, thisZone, sigfigs, snapLength, network}).
-record(packetHeader, {sec, uSec, savedLength, realLength}).
-record(ipV4Header, {tos, id, flags, fragmentOffset, ttl, protocol, src, dest, options, payload}).
%hex_to_bin(Str) -> << << (erlang:list_to_integer([H], 16)):4 >> || H <- Str >>.

%my_func(FILE) ->
%    {ok, Binary} = file:read_file(FILE),
%    {_,_, Packet} = get_packet(extract_pcap_header(Binary)),
%    extract_ip_header(Packet).
open_file(FileName) ->
  file:open(FileName, [read, binary, raw]).

read_all([{error, eof} | _], _, _) -> ok;
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
    {error, Any} -> {error, Any}
  end.

packet_reader(File) -> [read_packet(File) | fun() -> packet_reader(File) end ].

%extract_ip_header(Binary) ->
%  <<Version:4/big, IHL:4/big, ToS:8/big, TotalLength:16/big,
%    Id:16/big, Flags:3>>
%    <<IPFamily:4/big, IPHeaderLength:4/big, IPTos:16/big, IPLen:16, IPId:16, IPOff:16, IPTtl:8, IPP:8, IPSum:16,
%IP_add_src_3:8, IP_add_src_2:8, IP_add_src_1:8, IP_add_src_0:8,
%IP_add_dst_3:8, IP_add_dst_2:8, IP_add_dst_1:8, IP_add_dst_0:8>> = Binary,
%io:format("src : ~p.~p.~p.~p~ndst : ~p.~p.~p.~p~n", [IP_add_src_3, IP_add_src_2, IP_add_src_1, IP_add_src_0,
%IP_add_dst_3, IP_add_dst_2, IP_add_dst_1, IP_add_dst_0]).

%extract_ip_header_option(Data, 0, PayloadLength) ->
%  {<< >>, Data:PayloadLength/binary};
%extract_ip_header_option(Data, OptionLength, PayloadLength) ->
%  <<Options:OptionLength/binary, Payload:PayloadLength/binary>> = Data,
%  {Options, Payload}.

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
      io:format("IHL ~p, Length ~p, OptionLen ~p, PayloadLen ~p RestLen ~p~nRest :~p~n", [IHL, Length, OptionLen, PayloadLen, byte_size(Rest), Rest]),
      <<Options:OptionLen/binary, RestPayload:PayloadLen/binary>> = Rest,
      IpPacket = #ipV4Header{tos = TOS, id = Identification, flags = Flags,
        fragmentOffset = FragOffset, ttl = TTL, protocol = Protocol,
        src = SourceIP, dest = DestinationIP,
        options = Options, payload = RestPayload},
      {ok, {ipv4, IpPacket}};
    _ -> {error, paylod_parse}
end
.

link_type_null_parser(Payload) ->
  <<ProtocolFamily:32/native, Rest/binary>> = Payload,
  io:format("~p~n", [ProtocolFamily]),
  try ProtocolFamily of
    ?PF_INET -> ip_parser(Rest);
    Any -> {error, {unsoported_pf, Any}}
  catch
    error:Any -> {error, Any}
  end
.
get_link_type_parser(NetWorkType) when NetWorkType =:= ?LINKTYPE_NULL ->
  {ok, fun(P) -> link_type_null_parser(P) end}.

%% End of Module.
