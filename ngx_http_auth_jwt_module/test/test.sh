#!/usr/bin/env bash

RED='\033[01;31m'
GREEN='\033[01;32m'
NONE='\033[00m'

test_jwt () {
  local name=$1
  local path=$2
  local expect=$3
  local extra=$4

  cmd="curl -X GET -o /dev/null --silent --head --write-out '%{http_code}' http://localhost:8000$path -H 'cache-control: no-cache' $extra"

  test=$( eval ${cmd} )
  if [ "$test" -eq "$expect" ];then
    echo -e "${GREEN}${name}: passed (${test})${NONE}";
  else
    echo -e "${RED}${name}: failed (${test})${NONE}";
  fi
}

main() {
  local V_HS256=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmaXJzdE5hbWUiOiJXdW1pbmciLCJsYXN0TmFtZSI6IkxpdSIsImVtYWlsQWRkcmVzcyI6Ind1bWluZ2xpdUAxNjMuY29tIiwicm9sZXMiOlsiYWRtaW4iXSwiZXhwIjoxOTA4ODM1MjAwLCJpYXQiOjE0ODg4MTk2MDB9.XDyxtPstYDDUH9nnhA5dO_Ok8oIC4HMWoymi2z7zHS8
  local V_HS384=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9.eyJmaXJzdE5hbWUiOiJXdW1pbmciLCJsYXN0TmFtZSI6IkxpdSIsImVtYWlsQWRkcmVzcyI6Ind1bWluZ2xpdUAxNjMuY29tIiwicm9sZXMiOlsiYWRtaW4iXSwiZXhwIjoxOTA4ODM1MjAwLCJpYXQiOjE0ODg4MTk2MDB9.A9Fk86Q7Z-jhVX2ry0w5zSEDvAM9IPEnyq8JvI0Q3VUX1TBVLqhpoFB-YzXaH5tP
  local V_HS512=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJmaXJzdE5hbWUiOiJXdW1pbmciLCJsYXN0TmFtZSI6IkxpdSIsImVtYWlsQWRkcmVzcyI6Ind1bWluZ2xpdUAxNjMuY29tIiwicm9sZXMiOlsiYWRtaW4iXSwiZXhwIjoxOTA4ODM1MjAwLCJpYXQiOjE0ODg4MTk2MDB9.mxdJ5GU3LCABsv-wdLeeGq41dKC83uhYLrksTsyMhnW0H9WeOUeGNNn0G1hcoAaZuqxegZXKDps0l0hNmBvPYg

  test_jwt "Valid HS256 test" "/HS256/" "200" "--header \"Authorization: Bearer ${V_HS256}\""
  test_jwt "Valid HS384 test" "/HS384/" "200" "--header \"Authorization: Bearer ${V_HS384}\""
  test_jwt "Valid HS512 test" "/HS512/" "200" "--header \"Authorization: Bearer ${V_HS512}\""

  local IV_HS256=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmaXJzdE5hbWUiOiJXdW1pbmciLCJsYXN0TmFtZSI6IkxpdSIsImVtYWlsQWRkcmVzcyI6Ind1bWluZ2xpdUAxNjMuY29tIiwicm9sZXMiOlsiYWRtaW4kXSwiZXhwIjoxOTA4ODM1MjAwLCJpYXQiOjE0ODg4MTk2MDB9.XDyxtPstYDDUH9nnhA5dO_Ok8oIC4HMWoymi2z7zHS8
  local IV_HS384=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9.eyJmaXJzdE5hbWUiOiJXdW1pbmciLCJsYXN0TmFtZSI6IkxpdSIsImVtYWlsQWRkcmVzcyI6Ind1bWluZ2xpdUAxNjMuY29tIiwicm9sZXMiOlsiYWRtaW4iXpwiZXhwIjoxOTA4ODM1MjAwLCJpYXQiOjE0ODg4MTk2MDB9.A9Fk86Q7Z-jhVX2ry0w5zSEDvAM9IPEnyq8JvI0Q3VUX1TBVLqhpoFB-YzXaH5tP
  local IV_HS512=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJmaXJzdE5hbWUiOiJXdW1pbmciLCJsYXN0TmFtZSI6IkxpdSIsImVtYWlsQWRkcmVzcyI6Ind1bWluZ2xpdUAxNjMuY29tIiwicm9sZXMiOlsiYWRtaW4iXSwiZzhwIjoxOTA4ODM1MjAwLCJpYXQiOjE0ODg4MTk2MDB9.mxdJ5GU3LCABsv-wdLeeGq41dKC83uhYLrksTsyMhnW0H9WeOUeGNNn0G1hcoAaZuqxegZXKDps0l0hNmBvPYg

  test_jwt "Invalid HS256 test" "/HS256/" "403" "--header \"Authorization: Bearer ${IV_HS256}\""
  test_jwt "Invalid HS384 test" "/HS384/" "403" "--header \"Authorization: Bearer ${IV_HS384}\""
  test_jwt "Invalid HS512 test" "/HS512/" "403" "--header \"Authorization: Bearer ${IV_HS512}\""

  local V_RS256=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmaXJzdE5hbWUiOiJXdW1pbmciLCJsYXN0TmFtZSI6IkxpdSIsImVtYWlsQWRkcmVzcyI6Ind1bWluZ2xpdUAxNjMuY29tIiwicm9sZXMiOlsiYWRtaW4iXSwiZXhwIjoxOTA4ODM1MjAwLCJpYXQiOjE0ODg4MTk2MDB9.Ha2pzKBXoThnH_T1HEnsXpgAKvSglMB9U6SmDwE8rvAzfzthFO3677GZiIWPgJnmbsVQ56QVBQRVPp3pkdm_DAttl6ek9ZJQLcsYaPNoQkcviwvjfK_JsMyy_-KBVwX5azBG0dwlLHVZDD9PSj_UtxJ6gm-ixJhW7xhirZ16QYMPP5TjcsfIWrKyyjF0rOTjaOvi_hMKB6iBtuKlWKU1JBf2ePWI10lO9aZK6L8m7OHGhjsHSgiQwlLq-tVgoISdM89HxzsNbtj4AYbBKkS1jpsTkwb45IOVi3C5jFWotyv2KtAtDRDklXvZe4IJO7mgGdSJ6N4nwQOmRS8GR_xLiw
  local V_RS384=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzM4NCJ9.eyJmaXJzdE5hbWUiOiJXdW1pbmciLCJsYXN0TmFtZSI6IkxpdSIsImVtYWlsQWRkcmVzcyI6Ind1bWluZ2xpdUAxNjMuY29tIiwicm9sZXMiOlsiYWRtaW4iXSwiZXhwIjoxOTA4ODM1MjAwLCJpYXQiOjE0ODg4MTk2MDB9.nCK4jtUINxbtTmaUjg2ihIO-lLsCIvICgQRuZhgVGTEPH6e7Xoyi-3bPu18ccABsKeTbaNJqoVHVqktNJF-43mz134CFWV-ZlpX1MJc3oQb1wgTFZzdtdPlyo_K5MXrYNZxsDeq2ZDH55y_CDwOMKKI5wEA0baQIOii1bJRZjAJGu6qs9y7fzXwnjIBuWMRC321-sWy_dd1WqsZc2UkTUZPbiYRGLJdQI4Ky5BunBAf4m6H5tArxDaulM9rVCLY4Hab6Yg2NZIJwlTH7XjIfnMbnXQ2MYF5BgJt5QumZJp8fe7Uqb7_hLs5VgEOUhG9j5V4cIg_2kLgbo3k5LUKDAQ
  local V_RS512=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiJ9.eyJmaXJzdE5hbWUiOiJXdW1pbmciLCJsYXN0TmFtZSI6IkxpdSIsImVtYWlsQWRkcmVzcyI6Ind1bWluZ2xpdUAxNjMuY29tIiwicm9sZXMiOlsiYWRtaW4iXSwiZXhwIjoxOTA4ODM1MjAwLCJpYXQiOjE0ODg4MTk2MDB9.PL2KKrwBi1sQneuuoYfItnfjc_R_p0-MxKGINQEwfmq6RBwNiSZaezSc5HxOmC0JihI5eAIZD685Wsbj-EyvVzsDSb74hKGn5b0mUriT5EXYSW4uP3c1H5P1bb13PS9cMZw74ncnjiGOHcPRuGm3sHBhRpyBqM_lGFmMgnbcwJDhoFpFFHND7ADQbErepBDCT41PFIPe-2o4z0j4xJMrwzrdqBbqpRtGEnKIHxBWyfPSfjQRthKFHOnLyLxAO3bY8xTnJs_uZWGCnYWIpR4FUiVbcEnJuq3xWThQFep9R1qSWrSWAs4sAzYJFO2lSnNf59KDFQyKWxDEtDycnrMvzQ

  test_jwt "Valid RS256 test" "/RS256/" "200" "--header \"Authorization: Bearer ${V_RS256}\""
  test_jwt "Valid RS384 test" "/RS384/" "200" "--header \"Authorization: Bearer ${V_RS384}\""
  test_jwt "Valid RS512 test" "/RS512/" "200" "--header \"Authorization: Bearer ${V_RS512}\""

  local IV_RS256=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmaXJzdE5hbWUiOiJXdW1pbmciLCJsYXN0TmFtZSI6IkxpdSIsImVtYWlsQWRkcmVzcyI6Ind1bWluZ2xpdUAxNjMuY29tIiwicm9sZXMiOlsiYWRtaW4iXSwiZXhwIjoxOTA4ODM1MjAwLCJpYXQiOjE0ODg4MTk2MDB9.Ha2pzKBXoThnH_T1HEnsXpgAKvSglMB9U6SmDwE8rvAzfzthFO3677GZiIWPgJnmbsVQ56QVBQRVPp3pkdm_DAttl6ek9ZJQLcsYaPNoQkcviwvjfK_JsMyy_-KBVwX5azBG0dwlLHVZDD9PSj_UtxJ6gm-ixJhW7xhirZ16QYMPP5TjcsfIWrKyyjF0rOTjaOvi_hMKB6iBtuKlWKU1JBf2ePWI10lO9aZK6L8m7OHGhjsHSgiQwlLq-tVgoISdM89HxzsNbtj2AYbBKkS1jpsTkwb45IOVi3C5jFWotyv2KtAtDRDklXvZe4IJO7mgGdSJ6N4nwQOmRS8GR_xLiw
  local IV_RS384=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzM4NCJ9.eyJmaXJzdE5hbWUiOiJXdW1pbmciLCJsYXN0TmFtZSI6IkxpdSIsImVtYWlsQWRkcmVzcyI6Ind1bWluZ2xpdUAxNjMuY29tIiwicm9sZXMiOlsiYWRtaW4iXSwiZXhwIjoxOTA4ODM1MjAwLCJpYXQiOjE0ODg4MTk2MDB9.nCK4jtUINxbtTmaUjg2ihIO-lLsCIvICgQRuZhgVGTEPH6e7Xoyi-3bPu18ccABsKeTbaNJqoVHVqktNJF-43mz134CFWV-ZlpX1MJc3oQb1wgTFZzdtdPlyo_K5MXrYNZxsDeq2ZDH55y_CDwOMKKI5wEA0baQIOii1bJRZjAJGu6qs9y7fzXwnjIBuWMRC321-sWy_dd1WqsZc2UkTUZPbiYRGLJdQI4KydBunBAf4m6H5tArxDaulM9rVCLY4Hab6Yg2NZIJwlTH7XjIfnMbnXQ2MYF5BgJt5QumZJp8fe7Uqb7_hLs5VgEOUhG9j5V4cIg_2kLgbo3k5LUKDAQ
  local IV_RS512=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiJ9.eyJmaXJzdE5hbWUiOiJXdW1pbmciLCJsYXN0TmFtZSI6IkxpdSIsImVtYWlsQWRkcmVzcyI6Ind1bWluZ2xpdUAxNjMuY29tIiwicm9sZXMiOlsiYWRtaW4iXSwiZXhwIjoxOTA4ODM1MjAwLCJpYXQiOjE0ODg4MTk2MDB9.PL2KKrwBi1sQneuuoYfItnfjc_R_p0-MxKGINQEwfmq6RBwNiSZaezSc5HxOmC0JihI5eAIZD685Wsbj-EyvVzsDSb74hKGn5b0mUriT5EXYSW4uP3c1H5P1bb13PS9cMZw74ncnjiGOHcPRuGm3sHBhRpyBqM_lGFmMgnbcwJDhoFpFFHND7ADQbErepBDCT41PFIPe-2o4z0j4xJMrwzrdqBbqpdtGEnKIHxBWyfPSfjQRthKFHOnLyLxAO3bY8xTnJs_uZWGCnYWIpR4FUiVbcEnJuq3xWThQFep9R1qSWrSWAs4sAzYJFO2lSnNf59KDFQyKWxDEtDycnrMvzQ

  test_jwt "Invalid RS256 test" "/RS256/" "403" "--header \"Authorization: Bearer ${IV_RS256}\""
  test_jwt "Invalid RS384 test" "/RS384/" "403" "--header \"Authorization: Bearer ${IV_RS384}\""
  test_jwt "Invalid RS512 test" "/RS512/" "403" "--header \"Authorization: Bearer ${IV_RS512}\""

  local V_ES512=eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzUxMiJ9.eyJmaXJzdE5hbWUiOiJXdW1pbmciLCJsYXN0TmFtZSI6IkxpdSIsImVtYWlsQWRkcmVzcyI6Ind1bWluZ2xpdUAxNjMuY29tIiwicm9sZXMiOlsiYWRtaW4iXSwiZXhwIjoxOTA4ODM1MjAwLCJpYXQiOjE0ODg4MTk2MDB9.AQXnUfovhooQJEioYz4wpaEtUrOXksJBW7t9lVFpRPJtFnHingmMSMxXBnePskM6EF675ZpANx43-ym-48S8bC2bAS8HjASPeHTJI6Mzf6vvQ8IfVUbwtQV0TxhQphXSJSyIby_CDEIGQ_B9N9m7nhYvJo4oy2QFz4kfNhRNihtwalPg

  test_jwt "Valid ES512 test" "/ES512/" "200" "--header \"Authorization: Bearer ${V_ES512}\""

  local IV_ES512=eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzUxMiJ9.eyJmaXJzdE5hbWUiOiJXdW1pbmciLCJsYXN0TmFtZSI6IkxpdSIsImVtYWlsQWRkcmVzcyI6Ind1bWluZ2xpdUAxNjMuY29tIiwicm9sZXMiOlsiYWRtaW4iXSwiZXhwIjoxOTA4ODM1MjAwLCJpYXQiOjE0ODg4MTk2MDB9.AQXnUfovhooQJEioYz4wpaEtUrOXksJBW7t9lVFpRPJtFnHingmMSMxXBnePskM6EF675ZpANx43-ym-48S8bC2bAS8HjASPeHTJI6Mzf6vvQ8IfVUbwtQV0TxhQphXSJSyIby_CDEIGQ_B9N9m7nhYvJo4oy2qFz4kfNhRNihtwalPg

  test_jwt "Invalid ES512 test" "/ES512/" "403" "--header \"Authorization: Bearer ${IV_ES512}\""

  test_jwt "Conf merge test" "/insecure/" "200"
}

main "$@"
