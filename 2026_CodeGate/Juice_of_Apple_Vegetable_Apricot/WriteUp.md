# CodeGate 2026 CTF WriteUp
## Juice_of_Apple_Vegetable_Apricot (WEB)
1. 핵심 취약점 분석 (Vulnerabilities)
공격 기법: Argument Injection (jcmd) 및 JFR (Java Flight Recorder) Payload Smuggling 또는 HTTP Method Exception을 이용한 JFR 메모리 오염


2. 공격 원리 (Exploit Concept)


3. 핵식 공격기법 구성: JFR 시작 ➔ 에러 유발 ➔ 셸 실행


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



### StatusServlet 클래스 분석

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


### 힙 덤프 파일 생성해보기

공격 벡터
```
?pid=1+GC.heap_dump /tmp/test.hprof
```


<img width="698" height="257" alt="image" src="https://github.com/user-attachments/assets/f26f15b5-850b-46cc-89ab-140bc3b4ba35" />

<img width="1292" height="236" alt="image" src="https://github.com/user-attachments/assets/992b6615-6c88-4580-844b-4e4675428ae8" />

덤프 파일 쓰기를 시도했지만 서버에서는 jcmd 1 GC.heap_dump /tmp/test.hprof VM.version 다중 인자 명령어 생성되어 에러가 나는 것을 확인하였다.


### 다중인자를 허용하는 jcmd 옵션 사용하기

<img width="706" height="182" alt="image" src="https://github.com/user-attachments/assets/7da4ba92-0176-442c-8498-93c38f0a479c" />

공격 벡터
```
?pid=1+JFR.start+filename=/usr/local/tomcat/webapps/ROOT/WEB-INF/views/recording.jfr+duration=60s
```

경로 설정 이유
'''
RUN useradd -r -s /usr/sbin/nologin ctf \
    && chmod 1777 work temp logs webapps/ROOT/WEB-INF/views
'''

Dockerfile 내용을 보면 우리는 ctf 권한이고 ctf 권한에서 쓰기권한이 있는 경로는 webapps/ROOT/WEB-INF/views이다.

<img width="1153" height="168" alt="image" src="https://github.com/user-attachments/assets/f1b5b2b8-7136-4855-add6-3733e86afca2" />

해당 공격벡터로 공격 시도 시 정상 적으로 jfr 파일 이 생성된 메시지를 확인할 수 있다.


## 최종 시나리오
본 취약점들을 연계하여 플래그(Flag)를 탈취하는 전체 공격 흐름은 다음과 같다.
[단계 1: Argument Injection을 이용하여 쓰기 권한이 존재하는 경로에 파일 생성하기]

[단계 2: 에러를 발생시켜 에러내용을 방금 생성한 파일 내용으로 삽입하도록 유도]

[단계 3: 삽입한 내용을 실행]




## 실행 및 결과

__Step 1.__ 다중 파라미터를 허용하는 명령어를 삽입하여 jsp 파일 생성 

<img width="1246" height="275" alt="image" src="https://github.com/user-attachments/assets/b2bd909d-05c1-43b2-a749-de2bfa07f271" />




<br>
__Step 2.__ IllegalArgumentException 예외발생시켜 예외 내용이 생성한 exp.jsp 파일에 내용 삽입 (duration=5 로 설정하여 5초 안에 에러를 발생 시켜야 함)

<img width="1237" height="275" alt="image" src="https://github.com/user-attachments/assets/19671ae0-f24c-42c1-b6bc-c086cd204783" />


<br>

__Step 3.__ 발생된 예외 내용이 RCE 코드가 되어 /readflag 바이너리 파일이 실행되어 flag 파일 내용 확인

<img width="1249" height="368" alt="image" src="https://github.com/user-attachments/assets/23431d02-7a2f-416a-9700-66f225e12c5f" />




# 취약점 패치
## 취약한 코드
```

//util/inputValidator.java

public class InputValidator {

    private static final String BASH_SPECIAL = ";|&$`\\!(){}[]<>*?~^'\"";

    public static boolean containsBashSpecial(String value) {
        for (int i = 0; i < value.length(); i++) {
            if (BASH_SPECIAL.indexOf(value.charAt(i)) >= 0) return true;
        }
        return false;
    }

    public static boolean hasUnsafeParams(HttpServletRequest req) {
        Enumeration<String> paramNames = req.getParameterNames();
        while (paramNames.hasMoreElements()) {
            String value = req.getParameter(paramNames.nextElement());
            if (value != null && containsBashSpecial(value)) return true;
        }
        return false;
    }
}

```

";|&$`\\!(){}[]<>*?~^'\""; 이러한 문자들을 필터링하지만 공백을 필터링 하지 않아 여러가지 파라미터를 허용하는 jcmd 의 옵션을 사용하여 Argument Injection 공격이 가능하다.
