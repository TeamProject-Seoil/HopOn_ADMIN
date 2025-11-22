# 🚌 **HopOn – 스마트 모빌리티 통합 플랫폼**

> **사용자, 기사, 관리자**가 하나의 생태계로 연결되는  
> 실시간 위치 기반 **예약·운행·관리 올인원 시스템**

---

<table align="center">
  <tr>
    <td align="center">
      <img src="https://github.com/TeamProject-Seoil/HopOn_ADMIN_Page/blob/main/src/assets/%EC%82%AC%EC%9A%A9%EC%9E%90%EC%95%B1%20%ED%99%94%EB%A9%B4.png" width="220"/><br/>
      <sub><b>사용자 앱</b></sub>
    </td>
    <td align="center">
      <img src="https://github.com/TeamProject-Seoil/HopOn_ADMIN_Page/blob/main/src/assets/%EA%B8%B0%EC%82%AC%EC%95%B1%20%ED%99%94%EB%A9%B4.png" width="220"/><br/>
      <sub><b>기사 앱</b></sub>
    </td>
    <td align="center">
      <img src="https://github.com/TeamProject-Seoil/HopOn_ADMIN_Page/blob/main/src/assets/%EA%B4%80%EB%A6%AC%EC%9E%90%ED%8E%98%EC%9D%B4%EC%A7%80%20%ED%99%94%EB%A9%B4.png" width="500"/><br/>
      <sub><b>관리자 웹 대시보드</b></sub>
    </td>
  </tr>
</table>

---

# 📦 **Repository List**

| List | Repository | Link |
|------|------------|------|
| 사용자 앱 | 📱 **HopOn_UserAPP (Android)** | [![Repo](https://img.shields.io/badge/GitHub-HopOn__UserAPP-181717?logo=github)](https://github.com/TeamProject-Seoil/HopOn_UserApp) |
| 기사 앱 | 🚗 **HopOn_DriverAPP (Android)** | [![Repo](https://img.shields.io/badge/GitHub-HopOn__DriverAPP-181717?logo=github)](https://github.com/TeamProject-Seoil/HopOn_DriverApp) |
| 관리자 대시보드 | 🌐 **HopOn_ADMIN_Page (Vue 3)** | [![Repo](https://img.shields.io/badge/GitHub-HopOn__Admin_Page-181717?logo=github)](https://github.com/TeamProject-Seoil/HopOn_ADMIN_Page) |
| 사용자 + 기사 백엔드 | ⚙ **HopOn (Spring Boot)** | [![Repo](https://img.shields.io/badge/GitHub-HopOn__Backend-181717?logo=github)](https://github.com/TeamProject-Seoil/HopOn) |
| 관리자 백엔드 | ⚙ **HopOn_ADMIN (Spring Boot)** | [![Repo](https://img.shields.io/badge/GitHub-HopOn__Admin_Backend-181717?logo=github)](https://github.com/TeamProject-Seoil/HopOn_ADMIN) |

---

# 🌿 **프로젝트 소개**

**HopOn**은 실시간 GPS 기반으로  
사용자 → 기사 → 관리자 → 백엔드가 하나로 연결되는  
**End-to-End 모빌리티 운영 플랫폼**입니다.

- 사용자 → 예약, 실시간 위치, 승차·하차 알림  
- 기사 → 운행/지연 설정/GPS 업로드  
- 관리자 → 예약·회원·문의·권한 관리  

> **하나의 생태계에서 모든 서비스가 실시간으로 연동되는 것이 핵심입니다.**

---

# 👥 **팀원 소개**

<table>
  <tr>
    <th style="width:110px;">이름</th>
    <th style="width:80px;">역할</th>
    <th style="width:670px;">담당</th>
  </tr>
  <tr>
    <td><b>조건희</b></td>
    <td>팀장</td>
    <td>사용자/기사 앱 UI 개발, 주요 화면 구성, 컴포넌트 제작, PPT·일정 관리</td>
  </tr>
  <tr>
    <td><b>김민재</b></td>
    <td>팀원</td>
    <td>사용자/기사 앱 UI 개발, 주요 화면 구성, 발표</td>
  </tr>
  <tr>
    <td><b>유주현</b></td>
    <td>팀원</td>
    <td>사용자/기사 앱 UI 개발, 기능 일부 구현, 홍보 영상 제작</td>
  </tr>
  <tr>
    <td><b>최준영</b></td>
    <td>팀원</td>
    <td>사용자 앱 기능 개발, 메인 로직, 버스 데이터 API·Naver Maps 연동</td>
  </tr>
  <tr>
    <td><b>원동건</b></td>
    <td>팀원</td>
    <td>기사 앱 기능, 관리자 웹 개발, 로그인/JWT·권한 처리, 예약·문의·즐겨찾기 API, AWS 배포</td>
  </tr>
</table>



---

# ✨ **주요 기능**

## 👤 사용자(User App)
- 정류장 기반 예약·취소  
- 실시간 버스 위치 표시  
- 승차/하차 알림  
- 지연 여부 실시간 확인  
- 즐겨찾기 및 최근 이용  
- 네이버 지도 기반 경로 표시  

---

## 🚗 기사(Driver App)
- GPS Heartbeat 자동 송신  
- 예약 승객 리스트 실시간 표시  
- 지연 상태 설정  
- 운행 시작/종료  
- 승차/하차 처리 및 알림 전달  

---

## 🛠 관리자(Admin Page)
- 예약/회원/기사 대시보드  
- 문의·공지 관리  
- 관리자 권한 관리  
- Vue 3 기반 반응형 UI  

---

# 🛠 **기술 스택**

### 💻 Frontend(Admin)
Vue 3 · Vite · Pinia · Axios · Vue Router

### 📱 Android(User & Driver)
Java · Retrofit2 · Naver Map SDK · Material3

### ⚙ Backend
Spring Boot · Spring Security(JWT) · JPA · MySQL · SSE

### ☁ Infra
AWS EC2 · RDS · Route53 · Docker · Docker Compose · Nginx · Certbot · GitHub Actions

---

# 🚀 **배포 및 CI/CD**

- GitHub Actions → Docker 이미지 자동 빌드  
- EC2 → docker-compose pull & up 자동 반영  
- Nginx Reverse Proxy 구성  
- Route53 + 가비아 DNS 연동  
- Certbot HTTPS 자동 적용  
- Mixed Content 완전 제거  

---

# 🌐 **배포 구조**

| 구분 | 도메인 / 경로 | 연결 대상 | 설명 |
|------|----------------|------------|------|
| 사용자 프론트엔드 | GitHub Release | HopOn_UserApp | 사용자 앱 |
| 기사 프론트엔드 | GitHub Release | HopOn_DriverApp | 기사 앱 |
| 관리자 프론트엔드 | https://www.hoponhub.store | HopOn_ADMIN_Page | 관리자 웹 페이지 |
| 사용자·기사 백엔드 | `/api`, `/auth`, `/users` | HopOn Backend | 예약/운행/문의/즐겨찾기 API |
| 관리자 백엔드 | `/admin`, `/auth`, `/users`, `/reservations`, `/actuator/health` | HopOn_ADMIN Backend | 관리자 전용 API |

---
