%%%-------------------------------------------------------------------
%%% @author João Domingues, Loic Haas, Rick Wertenbroek
%%% @copyright (C) 2016, HEIG-VD
%%% @doc
%%%
%%% @end
%%% Created : 07. avr. 2016 09:36
%%%-------------------------------------------------------------------
-module(tshark_tests).
-author("João Domingues, Loic Haas, Rick Wertenbroek").

-include_lib("eunit/include/eunit.hrl").

protocol_from_int_test() ->
    Expected = "ICMP",
    Actual = tshark:ip_sub_protocol_from_int(1),
    ?assertEqual(Expected, Actual).

type_from_int_request_test() ->
    Expected = "Echo (ping) request",
    Actual = tshark:icmp_type_from_int(8),
    ?assertEqual(Expected, Actual).

type_from_int_reply_test() ->
    Expected = "Echo (ping) reply  ",
    Actual = tshark:icmp_type_from_int(0),
    ?assertEqual(Expected, Actual).

string_ttl_test() ->
    Expected = "ttl=64",
    Actual = tshark:string_ttl(64),
    ?assertEqual(Expected, Actual).

%% Big Endian !!!
string_id_test() ->
    Expected = "id=0xae4b",
    Actual = tshark:string_id(44619),
    ?assertEqual(Expected, Actual).

% Test du mode normal
result_from_ping_pcap_test() ->
    {ok, Expected} = file:read_file(data_dir("result_normal.txt")),
    {ok, Actual} = tshark:tshark_from_file(data_dir("ping.pcap")),
    ?assertEqual(binary_to_list(Expected), lists:flatten(Actual)).

% Test du mode verbeux
result_from_ping_pcap_verbose_test() ->
    {ok, Expected} = file:read_file(data_dir("result_verbose.txt")),
    {ok, Actual} = tshark:tshark_from_file_verbose(data_dir("ping.pcap")),
    ?assertEqual(binary_to_list(Expected), lists:flatten(Actual)).

simple_test() ->
  tshark:test("../ping.pcap"),
  ?assert(true).

data_dir(File) ->
    code:lib_dir(mcs_tshark, test) ++ "/data/" ++ File.
