# 1단계: 빌드 (Maven + JDK 21)
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /app

# 의존성 캐싱 위해 pom.xml 먼저 복사
COPY pom.xml .
RUN mvn -B dependency:go-offline

# 소스 코드 복사
COPY src ./src

# 실제 빌드 (테스트는 일단 스킵)
RUN mvn -B clean package -DskipTests

# 2단계: 실행용 가벼운 이미지 (JRE 21)
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app

# 빌드 결과 jar 복사
COPY --from=build /app/target/*.jar app.jar

# 운영 프로필 쓰면 이렇게
ENV SPRING_PROFILES_ACTIVE=prod

# HopOn_ADMIN은 8081로 띄운다고 가정
EXPOSE 8081
ENTRYPOINT ["java", "-jar", "/app/app.jar", "--server.port=8081"]
