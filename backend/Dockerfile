# 빌드 스테이지
FROM openjdk:17-jdk-alpine AS build

WORKDIR /app

# Gradle 설정 파일들 복사
COPY gradlew .
COPY gradle gradle
COPY build.gradle .
COPY settings.gradle .

# 실행 권한 부여
RUN chmod +x ./gradlew

# 의존성 다운로드 (캐시 최적화)
RUN ./gradlew dependencies --no-daemon

# 소스코드 복사 및 빌드
COPY src src
RUN ./gradlew build --no-daemon -x test

# 프로덕션 스테이지
FROM openjdk:17-jre-alpine

WORKDIR /app

# 시간대 설정
RUN apk add --no-cache tzdata
ENV TZ=Asia/Seoul

# JAR 파일 복사
COPY --from=build /app/build/libs/*.jar app.jar

# 포트 노출
EXPOSE 8080

# 애플리케이션 실행
ENTRYPOINT ["java", "-jar", "app.jar"]