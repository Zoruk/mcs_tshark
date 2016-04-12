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

simple_test() ->
  tshark:test("../ping.pcap"),
  ?assert(true).
