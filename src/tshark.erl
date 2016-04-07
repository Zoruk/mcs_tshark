-module(tshark).

%% tshark: tshark library's entry point.

-export([open_file/1, test/1]).
%% API

-record(pcapHeader, {magicNumber, versionMajor, versionMinor, thisZone, sigfigs, snapLength, network}).
-record(packetHeader, {sec, uSec, savedLength, realLength}).
%-record(ipV4Header, {serviceType, totalLength, a}).
%hex_to_bin(Str) -> << << (erlang:list_to_integer([H], 16)):4 >> || H <- Str >>.

%my_func(FILE) ->
%    {ok, Binary} = file:read_file(FILE),
%    {_,_, Packet} = get_packet(extract_pcap_header(Binary)),
%    extract_ip_header(Packet).
open_file(FileName) ->
  file:open(FileName, [read, binary, raw]).

read_all([{error, eof} | _], _) -> ok;
read_all([{ok, Header, Payload} | T], Acc) ->
  io:format("Packet ~p~n", [Acc]),
  io:format("    Header : ~p~n", [Header]),
  io:format("    Payload : ~p~n", [Payload]),
  read_all(T(), Acc + 1).

test(FileName) ->
  {ok, File} = open_file(FileName),
  {ok, PcapHeader} = extract_pcap_header(File),
  io:format("PcapHeader ~p~n", [PcapHeader]),
  Reader = packet_reader(File),
  read_all(Reader, 0).
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
%    <<IPFamily:32, IPHeaderLength:8, IPTos:8, IPLen:16, IPId:16, IPOff:16, IPTtl:8, IPP:8, IPSum:16,
%      IP_add_src_3:8, IP_add_src_2:8, IP_add_src_1:8, IP_add_src_0:8,
%      IP_add_dst_3:8, IP_add_dst_2:8, IP_add_dst_1:8, IP_add_dst_0:8, Rest/binary>> = Binary,
%    io:format("src : ~p.~p.~p.~p~ndst : ~p.~p.~p.~p~n", [IP_add_src_3, IP_add_src_2, IP_add_src_1, IP_add_src_0,
%							IP_add_dst_3, IP_add_dst_2, IP_add_dst_1, IP_add_dst_0]),
%    Rest.


%% End of Module.
