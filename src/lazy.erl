%%%-------------------------------------------------------------------
%%% @author Loïc Haas
%%% @copyright (C) 2016, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 17. mars 2016 11:09
%%%-------------------------------------------------------------------
-module(lazy).
-author("Loïc Haas").

%% API
-export([map/2, map/3, filter/3, foldl/4, foldl/3]).

map(_, 0,        _) -> [];
map(F, N, [V | LT]) -> [F(V) | map(F, N-1, LT())].

map(_, [lazy_end | _]) -> [];
map(F,       [V | LT]) -> [F(V) | map(F, LT())].

filter(_, 0, _) -> [];
filter(F, N, [V | LT]) ->
  case F(V) of
    true -> [V | filter(F, N-1, LT())];
    _ -> filter(F, N-1, LT())
  end.


foldl(_, Acc, 0, _) -> Acc;
foldl(F, Acc, N, [V | LT]) -> foldl(F, F(V, Acc), N-1, LT()).

foldl(_, Acc, [lazy_end|_]) -> Acc;
foldl(F, Acc, [V | LT]    ) -> foldl(F, F(V, Acc), LT()).

