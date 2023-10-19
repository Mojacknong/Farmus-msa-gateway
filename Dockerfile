FROM openjdk:11-jdk
VOLUME /tmp
ARG JAR_FILE=build/libs/farmus-gateway-0.0.1-SNAPSHOT.jar
COPY ${JAR_FILE} farmus-gateway.jar

ENTRYPOINT ["java","-jar","/farmus-gateway.jar"]