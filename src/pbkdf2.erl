% Licensed under the Apache License, Version 2.0 (the "License"); you may not
% use this file except in compliance with the License. You may obtain a copy of
% the License at
%
%   http://www.apache.org/licenses/LICENSE-2.0
%
% Unless required by applicable law or agreed to in writing, software
% distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
% WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
% License for the specific language governing permissions and limitations under
% the License.

-module(pbkdf2).

-export([pbkdf2/3, pbkdf2/4, verify/2]).

-define(MAX_DERIVED_KEY_LENGTH, (1 bsl 32 - 1)).
-define(SHA1_OUTPUT_LENGTH, 20).

%% Current scheme, much stronger.
-spec pbkdf2(binary(), binary(), integer()) -> binary().
pbkdf2(Password, Salt, Iterations) ->
    {ok, Result} = pbkdf2(Password, Salt, Iterations, ?SHA1_OUTPUT_LENGTH),
    Result.

-spec pbkdf2(binary(), binary(), integer(), integer())
    -> {ok, binary()} | {error, derived_key_too_long}.
pbkdf2(_Password, _Salt, _Iterations, DerivedLength)
    when DerivedLength > ?MAX_DERIVED_KEY_LENGTH ->
    {error, derived_key_too_long};
pbkdf2(Password, Salt, Iterations, DerivedLength) ->
    L = ceiling(DerivedLength / ?SHA1_OUTPUT_LENGTH),
    <<Bin:DerivedLength/binary,_/binary>> =
        iolist_to_binary(pbkdf2(Password, Salt, Iterations, L, 1, [])),
    {ok, list_to_binary(to_hex(Bin))}.

-spec pbkdf2(binary(), binary(), integer(), integer(), integer(), iolist())
    -> iolist().
pbkdf2(_Password, _Salt, _Iterations, BlockCount, BlockIndex, Acc)
    when BlockIndex > BlockCount ->
    lists:reverse(Acc);
pbkdf2(Password, Salt, Iterations, BlockCount, BlockIndex, Acc) ->
    Block = pbkdf2(Password, Salt, Iterations, BlockIndex, 1, <<>>, <<>>),
    pbkdf2(Password, Salt, Iterations, BlockCount, BlockIndex + 1, [Block|Acc]).

-spec pbkdf2(binary(), binary(), integer(), integer(), integer(),
    binary(), binary()) -> binary().
pbkdf2(_Password, _Salt, Iterations, _BlockIndex, Iteration, _Prev, Acc)
    when Iteration > Iterations ->
    Acc;
pbkdf2(Password, Salt, Iterations, BlockIndex, 1, _Prev, _Acc) ->
    InitialBlock = crypto:sha_mac(Password,
        <<Salt/binary,BlockIndex:32/integer>>),
    pbkdf2(Password, Salt, Iterations, BlockIndex, 2,
        InitialBlock, InitialBlock);
pbkdf2(Password, Salt, Iterations, BlockIndex, Iteration, Prev, Acc) ->
    Next = crypto:sha_mac(Password, Prev),
    pbkdf2(Password, Salt, Iterations, BlockIndex, Iteration + 1,
                   Next, crypto:exor(Next, Acc)).

%% verify two lists for equality without short-circuits to avoid timing attacks.
-spec verify(string(), string(), integer()) -> boolean().
verify([X|RestX], [Y|RestY], Result) ->
    verify(RestX, RestY, (X bxor Y) bor Result);
verify([], [], Result) ->
    Result == 0.

-spec verify(binary(), binary()) -> boolean();
            (list(), list()) -> boolean().
verify(<<X/binary>>, <<Y/binary>>) ->
    verify(binary_to_list(X), binary_to_list(Y));
verify(X, Y) when is_list(X) and is_list(Y) ->
    case length(X) == length(Y) of
        true ->
            verify(X, Y, 0);
        false ->
            false
    end;
verify(_X, _Y) -> false.

-spec ceiling(number()) -> integer().
ceiling(X) ->
    T = erlang:trunc(X),
    case (X - T) of
        Neg when Neg < 0 -> T;
        Pos when Pos > 0 -> T + 1;
        _ -> T
    end.

-spec to_hex(binary()) -> list();
            (list()) -> list().
to_hex([]) ->
    [];
to_hex(Bin) when is_binary(Bin) ->
    to_hex(binary_to_list(Bin));
to_hex([H|T]) ->
    [to_digit(H div 16), to_digit(H rem 16) | to_hex(T)].

to_digit(N) when N < 10 -> $0 + N;
to_digit(N)             -> $a + N-10.
