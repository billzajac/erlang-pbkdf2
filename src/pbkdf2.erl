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

-export([hash_password/4,test/0]).
-define(MAX_DERIVED_KEY_LENGTH, (1 bsl 32 -1)).
-define(SHA1_OUTPUT_LENGTH, 20).

-spec hash_password(binary(), binary(), integer(), integer()) -> {ok, binary()}.
hash_password(_Password, _Salt, _Iterations, DerivedLength) when DerivedLength > ?MAX_DERIVED_KEY_LENGTH ->
    {error, derived_key_too_long};
hash_password(Password, Salt, Iterations, DerivedLength) ->
    L = ceiling(DerivedLength / ?SHA1_OUTPUT_LENGTH),
    %%R = DerivedLength - (L - 1) * ?SHA1_OUTPUT_LENGTH,
    Bin = iolist_to_binary(hash_password1(Password, Salt, Iterations, L)),
    {ok, to_hex(binary:part(Bin, {0, DerivedLength}))}.

hash_password1(Password, Salt, Iterations, BlockCount) ->
    hash_password2(Password, Salt, Iterations, BlockCount, 1, []).

hash_password2(_Password, _Salt, _Iterations, BlockCount, BlockIndex, Acc) when BlockIndex > BlockCount ->
    lists:reverse(Acc);
hash_password2(Password, Salt, Iterations, BlockCount, BlockIndex, Acc) ->
    T = hash_password3(Password, Salt, Iterations, BlockIndex),
    hash_password2(Password, Salt, Iterations, BlockCount, BlockIndex + 1, [T|Acc]).

hash_password3(Password, Salt, Iterations, BlockIndex) ->
    hash_password4(Password, Salt, Iterations, BlockIndex, 2,
                   crypto:sha_mac(Password, <<Salt/binary,BlockIndex:32/integer>>)).

hash_password4(Password, Salt, Iterations, BlockIndex, Iteration, Acc) ->
    hash_password5(Password, Salt, Iterations, BlockIndex, Iteration, Acc, Acc).

hash_password5(_Password, _Salt, Iterations, _BlockIndex, Iteration, _Prev, Acc) when Iteration > Iterations ->
    Acc;
hash_password5(Password, Salt, Iterations, BlockIndex, Iteration, Prev, Acc) ->
    Next = crypto:sha_mac(Password, Prev),
    hash_password5(Password, Salt, Iterations, BlockIndex, Iteration + 1,
                   Next, do_bxor(Acc, Next)).

ceiling(X) ->
    T = erlang:trunc(X),
    case (X - T) of
        Neg when Neg < 0 -> T;
        Pos when Pos > 0 -> T + 1;
        _ -> T
    end.

do_bxor(B1, B2) when is_binary(B1), is_binary(B2) ->
    list_to_binary(do_bxor(binary_to_list(B1), binary_to_list(B2)));
do_bxor(L1, L2) when is_list(L1), is_list(L2) ->
    do_bxor(lists:reverse(L1), lists:reverse(L2), []).

do_bxor([], [], Acc) ->
    Acc;
do_bxor([I1|Rest1], [I2|Rest2], Acc) ->
    do_bxor(Rest1, Rest2, [I1 bxor I2|Acc]).

to_hex([]) ->
    [];
to_hex(Bin) when is_binary(Bin) ->
    to_hex(binary_to_list(Bin));
to_hex([H|T]) ->
    [to_digit(H div 16), to_digit(H rem 16) | to_hex(T)].

to_digit(N) when N < 10 -> $0 + N;
to_digit(N)             -> $a + N-10.

test() ->
    assertEqual("0c60c80f961f0e71f3a9b524af6012062fe037a6",
                hash_password(<<"password">>, <<"salt">>, 1, 20)),
    assertEqual("ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957",
                hash_password(<<"password">>, <<"salt">>, 2, 20)),
    assertEqual("6b4e26125c25cf21ae35ead955f479ea2e71f6ff",
                hash_password(<<"password">>, <<"salt">>, 3, 20)),
    assertEqual("4b007901b765489abead49d926f721d065a429c1",
                hash_password(<<"password">>, <<"salt">>, 4096, 20)),
    assertEqual("3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038",
                hash_password(<<"passwordPASSWORDpassword">>, <<"saltSALTsaltSALTsaltSALTsaltSALTsalt">>,
                              4096, 25)),
    assertEqual("56fa6aa75548099dcc37d7f03425e0c3",
                hash_password(<<"pass\0word">>, <<"sa\0lt">>, 4096, 16)),
    assertEqual("eefe3d61cd4da4e4e9945b3d6ba2158c2634e984",
                hash_password(<<"password">>, <<"salt">>, 16777216, 20)),
    finished.

assertEqual(Expected, {ok, Expected}) ->
    io:format("ok~n");
assertEqual(Expected, {ok, Actual}) ->
    io:format("error! expected: ~n~s~n but got ~n~s~n~n", [Expected, Actual]).
