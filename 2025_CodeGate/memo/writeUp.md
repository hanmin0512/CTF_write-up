# CodeGate 2026 CTF WriteUp
## memo (WEB)
1. 핵심 취약점 분석 (Vulnerabilities)
공격 기법: Blind XS-Leak (HTTP/2 Stream Exhaustion)

응답 무한 대기 (Hanging) 취약점: ImageController에서 요청한 이미지 파일이 존재하지 않을 경우, 에러(404 Not Found)를 반환하거나 응답 객체를 명시적으로 종료(res.end())하지 않아 서버와 브라우저 간의 연결이 끊기지 않고 무한 대기 상태에 빠지는 결함이 존재함.

관리자 API 부분 일치 (Partial Match) 로직: 관리자(Admin) 전용 엔드포인트인 /image/admin은 파일명 전체가 아닌, 시작 부분(startsWith)만 일치해도 해당 파일을 찾아 반환하는 논리적 취약점을 가짐. 이를 통해 긴 랜덤 해시값을 가진 플래그 파일의 이름을 한 글자씩 유추할 수 있음.

2. 공격 원리 (Exploit Concept)
현대 브라우저와 Nginx 서버가 사용하는 HTTP/2 프로토콜의 동시 스트림(Concurrent Streams) 제한을 악용함.

Nginx는 하나의 연결 통로 안에서 동시에 처리할 수 있는 요청(스트림)의 개수를 128개로 제한(http2_max_concurrent_streams 128)하고 있음.
(정확히는 **'클라이언트와 서버가 맺은 단일 TCP 연결(Connection) 당 128개'**이다.)
악성 메모에 128개의 이미지 태그(<img>)를 삽입하여 관리자 봇(Bot)이 접근하게 만들면, 이 제한 수치를 인위적으로 고갈시킬 수 있음.

3. Blind Oracle 구성 (참/거짓 추측 근거)
페이지 접속 시 백그라운드에서 실행되는 '조회수 증가 API(POST /view)'의 성공 여부를 관찰하여 파일 존재 여부를 판별함.

False (Miss / 파일이 없을 때): * 128개 요청 이미지가 전부 서버에 존재하지 않는 가짜 파일일 경우.

서버가 응답을 닫지 않아 브라우저의 128개 통로(Stream)가 모두 대기 상태로 막힘.

페이지 로딩 후 실행되어야 할 '조회수 증가 요청'이 네트워크 통로를 할당받지 못해 타임아웃 발생 ➔ 조회수 증가 X (0)

True (Hit / 파일이 존재할 때): * 128개 요청 중 단 1개라도 이름의 시작 부분이 일치하는 진짜 파일(플래그 파일)이 섞여 있을 경우.

서버가 진짜 사진을 반환한 후 해당 연결 1개를 정상적으로 종료해 줌.

통로 1개가 비게 되면서, 대기하던 '조회수 증가 요청'이 서버로 전달됨 ➔ 조회수 증가 O (+1)

### getAdminImagePath(filename: string) 함수 분석
  
```typescript

getAdminImagePath(filename: string): string | null { //filename을 입력받아  string 이거나 null을 반환함
    const imagePath = this.resolveSafePath(filename); //LFI 공격 방지를 위한 resolveSafePath함수로 점검 (../ 방지)

    if (imagePath && existsSync(imagePath)) return imagePath; // 정확한 이미지 파일명 요청시 반환

    const files = readdirSync(this.getImageDir()); //정확하게 일치한 파일명이 없다면 images 폴더 안에 있는 파일의 이름 목록을 불러와 files에 배열로 저장
    const matched = files.find(file => file.startsWith(filename)); // 사용자가 입력한 글자가 시작 부분이 일치하면 matched 변수에 저장

    if (!matched) return null; // 시작하는 부분조차 일치하지 않는다면 null을 반환 (여기서 응답 무한대기 취약점으로 이어진다. 정상은 에러처리 해야 함)

    return this.resolveSafePath(matched);
}

```

<p align = "center"> 
코드1
</p>





### getImageAdmin() 함수 분석

```typescript

@Get('/admin')
@UseGuards(AdminGuard)
async getImageAdmin(
    @Query('filename') filename: string,
    @Req() req: Request,
    @Res() res: Response
): Promise<void> {
    const site = req.get('sec-fetch-site'); // 요청이 같은 도메인에서 왔는지 검사

    if (site !== 'same-origin') throw new HttpException('Unauthorized.', 401); // 같은 도메인에서 요청한 것이 아니라면 401 에러

    if (!filename) throw new HttpException('filename is required.', 400); //filename이 null이거나 없다면 400 에러

    const imagePath = this.imageService.getAdminImagePath(filename);
    if (!imagePath) return; // 404 에러가 아닌 함수만 빠져나가기 때문에 무한대기상태에 빠지며 이부분이 HTTP/2 스트림 128개를 고갈시키는 직접적인 원인이다.

    return res.sendFile(imagePath);
}

```

<p align = "center"> 
코드2
</p>


### incrementViews() 함수 분석

```typescript
// 특정 memo에 접근하여 해당 memo가 화면에 랜더링될 때 자동으로 호출됨 호출될 시 조회수 증가됨
// 하지만 HTTP/2 stream이 꽉차서 호출이 안될 시 조회수 증가x
@Post('/:id/view')
async incrementViews(@Param('id') id: string): Promise<ResponseDto> {
  await this.memoService.incrementViews(id);

  return { status: 200, message: 'Views incremented successfully' };
}

```

<p align = "center"> 
코드3
</p>


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


## 실행 및 결과

