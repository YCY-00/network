#include "EchoAssignment.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <arpa/inet.h>

// !IMPORTANT: allowed system calls.
// !DO NOT USE OTHER NETWORK SYSCALLS (send, recv, select, poll, epoll, fork
// etc.)
//  * socket
//  * bind
//  * listen
//  * accept
//  * read
//  * write
//  * close
//  * getsockname
//  * getpeername
// See below for their usage.
// https://github.com/ANLAB-KAIST/KENSv3/wiki/Misc:-External-Resources#linux-manuals

int EchoAssignment::serverMain(const char *bind_ip, int port,
                               const char *server_hello) {
  // Your server code
  // !IMPORTANT: do not use global variables and do not define/use functions
  // !IMPORTANT: for all system calls, when an error happens, your program must
  // return. e.g., if an read() call return -1, return -1 for serverMain.
  // 소켓 생성 및 서버 주소 설정
  int server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); // 소켓 생성: socket(통신_도메인(프로토콜/주소), 소켓_형태, 통신_프로토콜)
  struct sockaddr_in server_addr; // sockaddr_in 구조체 생성: sockaddr(소켓의 주소를 담는 구조체로, sa_family(주소체계 구분)와 sa_data(실 주소) 존재), sockaddr_in(sa_family가 주소(AF_INET)인 경우, sa_data 세분화: sin_port(포트번호), sin_addr(호스트 ip 주소), sin_zero(8byte dummy->sockaddr과 크기 일치))
  socklen_t len = sizeof(server_addr); // socklen_t: 소켓의 길이 및 크기 값에 대한 매개변수의 타입
  memset(&server_addr, 0, len); // memset(시작 주소, 초기값, 길이): 메모리 초기화

  server_addr.sin_family = AF_INET; // 고정값
  server_addr.sin_addr.s_addr = inet_addr(bind_ip); // inet_addr: ip 문자열을 in_addr 구조체(ipv4 주소 저장)에 맞게 변경
  server_addr.sin_port = htons(port); // atoi(): 문자열 정수 변환. htons(): 정수를 네트워크 바이트 순서(낮은 주소->높은 주소)로 변환

  // 소켓 바인딩
  int ret = bind(server_socket, (struct sockaddr *)&server_addr, len); //bind(소켓, 주소, 길이): 소켓에 ip 번호와 포트번호 지정
  // EXPECT_EQ(ret, 0); // ret이 0인지 테스트 -> bind는 성공 시 0을 반환하므로, 지정이 잘 되었는지 확인

  // 리스닝
  ret = listen(server_socket, 5); // listen(소켓, queueing의 최대 길이): 소켓을 수신 대기 상태로 전환. 일반적으로 backlog의 값은 5로, 그 이상은 kernel resource 소모
  // EXPECT_EQ(ret, 0);
  
  // 클라이언트 연결
  // std::vector<int> client_sockets; // std::vector: c++ 표준 라이브러리 동적 배열 컨테이너 템플릿 클래스

  while(true) { // 무한 반복
  // for (int i=0; i<100000; i++){
    // 클라이언트 주소 설정
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    memset(&client_addr, 0, client_len);
    // 연결 요청 수락
    int client_fd = accept(server_socket, (struct sockaddr *)&client_addr, &client_len); // accept(소켓, 클라이언트_정보_저장_버퍼, 연결_크기): 연결 요청을 수락하고, 통신을 위한 새로운 소켓 반환. 실패 시 -1 반환
    // 요청 수락 확인 및 검증
    if (client_fd < 0){
      close(server_socket);
      return -1;
    }
    /*
    if (client_fd >= 0) { // 연결 요청 수락 완료
      EXPECT_EQ(client_len, sizeof(client_addr));
      EXPECT_EQ(client_addr.sin_family, AF_INET);

      struct sockaddr_in temp_addr;
      socklen_t temp_len = sizeof(temp_addr);
      int ret = getsockname(client_fd, (struct sockaddr *)&temp_addr, &temp_len);
      EXPECT_EQ(ret, 0);
      EXPECT_TRUE((addr.sin_addr.s_addr == 0) ||
                  (addr.sin_addr.s_addr == temp_addr.sin_addr.s_addr));
      EXPECT_EQ(addr.sin_family, temp_addr.sin_family);
      EXPECT_EQ(addr.sin_port, temp_addr.sin_port);

      // client_sockets.push_back(client_fd); // 통신용 소켓 저장
    }
    */

    // client ip 주소 획득
    char client_ip[INET_ADDRSTRLEN]; // INET_ADDRSTRLEN: IPv4 주소의 가장 큰 문자열 표현(15)+종료 널 문자(1)=16, <arpa/inet.h>에서 정의
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip)); // inet_ntop(sin_family, ip 주소 포인터, 저장 버퍼, 버퍼 크기): 인터넷 네트워크 주소를 binary 형식에서 인터넷 표준 형식의 문자열로 변환
        
    // request 읽기
    char buffer[1024]; // 전송 데이터의 일반적인 패킷 크기
    ssize_t bytes_read = read(client_fd, buffer, sizeof(buffer) - 1); // read(소켓, 내용을 저장할 버퍼 변수, 데이터_크기): 소켓에서 데이터_크기만큼의 데이터를 읽어 버퍼에 저장
    buffer[bytes_read] = '\0';  // 문자열 끝에 Null 추가
    
    // response 결정
    std::string request(buffer);
    std::string response;
    // printf(request.c_str());
    if (request == "hello") { // 입력값이 hello인 경우(문자열 비교) -> server-hello
      response = std::string(server_hello); // std::string: 동적 문자열 클래스
    }
    else if (request == "whoami") { // 입력값이 whoami인 경우 -> client_ip
      response = std::string(client_ip);
    }
    else if (request == "whoru") { // 입력값이 whoru인 경우 -> server_ip
      response = std::string(bind_ip);
    }
    else { // 기타 -> 입력값
      response = request;
    }
        
    // response 반환
    write(client_fd, response.c_str(), response.length()); // response 반환
        
    // 기록 저장 및 통신 소켓 닫기
    submitAnswer(client_ip, buffer);
    close(client_fd);
  }

  // 클라이언트 소켓 검증 및 닫기
  /*
  EXPECT_EQ((int)client_sockets.size(), expected_accept);
  for (auto client_fd : client_sockets) { // client_fd의 타입을 자동으로 추론, client_sockets의 각 요소를 순차적으로 client_fd에 할당하여 반복문 진행
    int same_count = 0;
    for (auto client_fd2 : client_sockets) {
      if (client_fd == client_fd2)
        same_count++;
    }
    EXPECT_EQ(same_count, 1); // 소켓의 중복 여부 확인(중복 불가)
  }

  for (auto client_fd : client_sockets) {
    close(client_fd); // 각 통신용 소켓 닫기
  }
  */

  close(server_socket); // 서버 소켓 닫기

  return 0;
}

int EchoAssignment::clientMain(const char *server_ip, int port,
                               const char *command) {
  // Your client code
  // !IMPORTANT: do not use global variables and do not define/use functions
  // !IMPORTANT: for all system calls, when an error happens, your program must
  // return. e.g., if an read() call return -1, return -1 for clientMain.
  // 소켓 생성 및 서버 주소 설정
  int client_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  struct sockaddr_in server_addr;
  socklen_t len = sizeof(server_addr);
  memset(&server_addr, 0, len);

  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = inet_addr(server_ip);
  server_addr.sin_port = htons(port);
    
  // 서버 연결
  connect(client_socket, (struct sockaddr*)&server_addr, sizeof(server_addr));

  // request 전송
  write(client_socket, command, strlen(command));
    
  // response 읽기
  char buffer[1024]; // 전송 데이터의 일반적인 패킷 크기
  ssize_t bytes_read = read(client_socket, buffer, sizeof(buffer) - 1); // read(소켓, 내용을 저장할 버퍼 변수, 데이터_크기): 소켓에서 데이터_크기만큼의 데이터를 읽어 버퍼에 저장
  buffer[bytes_read] = '\0';  // 문자열 끝에 Null 추가

  std::string cmd(command);
  std::string response(buffer);
  if(cmd == "whoru" && response == "0.0.0.0"){ // 0.0.0.0을 서버 주소로 받은 경우
    strncpy(buffer, server_ip, sizeof(buffer) - 1); // 버퍼에 server_ip 주소 저장
    buffer[sizeof(buffer) - 1] = '\0';  // 문자열 끝에 Null 문자 추가

  }
    
  // 기록 저장 및 통신 소켓 닫기
  submitAnswer(server_ip, buffer);
  close(client_socket); // 클라이언트 소켓 닫기

  return 0;
}

static void print_usage(const char *program) {
  printf("Usage: %s <mode> <ip-address> <port-number> <command/server-hello>\n"
         "Modes:\n  c: client\n  s: server\n"
         "Client commands:\n"
         "  hello : server returns <server-hello>\n"
         "  whoami: server returns <client-ip>\n"
         "  whoru : server returns <server-ip>\n"
         "  others: server echos\n"
         "Note: each command is terminated by newline character (\\n)\n"
         "Examples:\n"
         "  server: %s s 0.0.0.0 9000 hello-client\n"
         "  client: %s c 127.0.0.1 9000 whoami\n",
         program, program, program);
}

int EchoAssignment::Main(int argc, char *argv[]) {

  if (argc == 0)
    return 1;

  if (argc != 5) {
    print_usage(argv[0]);
    return 1;
  }

  int port = atoi(argv[3]);
  if (port == 0) {
    printf("Wrong port number\n");
    print_usage(argv[0]);
  }

  switch (*argv[1]) {
  case 'c':
    return clientMain(argv[2], port, argv[4]);
  case 's':
    return serverMain(argv[2], port, argv[4]);
  default:
    print_usage(argv[0]);
    return 1;
  }
}
