# LINE CTF WEB (yapper catcher)
2025 LINE CTF WEB 부문 yapper catcher 문제 write up

## 개요
해당 보고서는 LINE CTF에서 나온 문제 **yapper catcher** 문제 풀이입니다. 파라미터 변조를 통해 bot이 특정 유저 포스팅 경로에 글을 쓰게하여 플래그 획득이 가능한 것을 확인하였습니다.

## 취약점 세부 사항
**_url_**
http://localhost:9001/bot/quote

**_method_**
`POST`

**_payload_**
username=attacker&id=[유저_포스팅_경로]

## 공격 시나리오
파리미터
