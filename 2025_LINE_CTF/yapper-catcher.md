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
파리미터 변조를 통해  LINE CTF WEB (yapper catcher)
2025 LINE CTF WEB 부문 yapper catcher 문제 write up

## 취약점 증명 및 검증

Step 1. 폼 안에 값을 기입하여 포스팅 시도하였습니다.
<img width="1468" height="705" alt="Step 1  폼 안에 값을 기입하여 포스팅 시도하였습니다" src="https://github.com/user-attachments/assets/7511eac5-8108-4bf4-9349-0f16483c6451" />

Step 2. Alice 사용자의 포스팅 경로를 확인하였습니다.
<img width="1465" height="716" alt="Step 2  Alice 사용자의 포스팅 경로를 확인하였습니다" src="https://github.com/user-attachments/assets/c1b49fe1-340d-47c1-9360-a314a2d86df2" />

Step 3. Alice 포스팅 공간에 새로운 포스팅을 시도하였습니다.
<img width="1468" height="680" alt="Step 3  Alice 포스팅 공간에 새로운 포스팅을 시도하였습니다" src="https://github.com/user-attachments/assets/468d7013-71f9-4814-a15e-280ab396cd50" />

Step 4. 요청 패킷 내의 payload를 확인하였습니다.
<img width="1433" height="736" alt="Step 4  요청 패킷 내의 payload를 확인하였습니다" src="https://github.com/user-attachments/assets/8b88a1be-29fd-4010-ba23-51ec98d6071c" />

Step 5. payload에 id(포스팅 경로)가 있다면 해당 경로에 포스팅을 하는 로직을 확인하였습니다.
<img width="654" height="387" alt="Step 5  payload에 id(포스팅 경로)가 있다면 해당 경로에 포스팅을 하는 로직을 확인하였습니다" src="https://github.com/user-attachments/assets/d93cc926-fe0a-4168-bc2c-05b3d066cbfe" />

Step 6. 봇에 id 값을 인젝션하여 자동 포스팅 시도하였습니다.
<img width="1465" height="756" alt="Step 6  봇에 id 값을 인젝션하여 자동 포스팅 시도하였습니다" src="https://github.com/user-attachments/assets/3cd2240e-0e1f-444d-a51d-6b96fb41378a" />

Step 7. 봇이 접근하는 로직을 확인하였습니다.
<img width="778" height="553" alt="Step 7  봇이 접근하는 로직을 확인하였습니다" src="https://github.com/user-attachments/assets/8ca33cd3-11f3-43c2-9cc1-11d1fc9872ba" />

Step 8. 봇이 접근하는 경로로 접근 시 새로운 글이 포스팅 된것을 확인하였습니다.
<img width="1451" height="759" alt="Step 8  봇이 접근하는 경로로 접근 시 새로운 글이 포스팅 된것을 확인하였습니다" src="https://github.com/user-attachments/assets/840021d2-c17c-4d0c-84ac-32479b0d42cb" />

Step 9. Alice 포스팅 비밀번호를 통해 복호화 하여 flag를 획득하였습니다.
<img width="1436" height="700" alt="Step 9  Alice 포스팅 비밀번호를 통해 복호화 하여 flag를 획득하였습니다" src="https://github.com/user-attachments/assets/0afd1d44-4e84-44e0-b271-558ad261ad8d" />

