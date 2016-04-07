%%%-------------------------------------------------------------------
%%% @author zoruk
%%% @copyright (C) 2016, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 07. avr. 2016 09:36
%%%-------------------------------------------------------------------
-module(tshark_tests).
-author("zoruk").

-include_lib("eunit/include/eunit.hrl").

simple_test() ->
  tshark:test("../ping.pcap"),
  ?assert(true).
