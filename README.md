# Spring Security + JWT (Spring 6.0)
This is the final implementation of Spring Security + JSON Web Tokens (JWT) for authorization and authentication. This will be used as an __integration__ for future projects, and to be configured accordingly based on the requirements.
> [!NOTE]
> If you plan on upgrading JDK version, check the [official documentation](https://spring.io/) for changes in the configurations.
### Task
- [x] Spring Security 6.0
- [x] JWT
- [ ] Refresh Tokens
- [ ] OAuth / Auth 2.0
## Setup Guide
__What you will need:__
+ __Apache Maven__ 3.9.8 or higher ([Apache Maven](https://maven.apache.org/))
+ __JDK__ 17 or higher ([Java](https://www.oracle.com/java/technologies/javase/jdk17-archive-downloads.html))
+ __PostgreSQL__ 14 or higher ([PostgreSQL](https://www.postgresql.org/download/))
+ An IDE of your choice (e.g., VSCode, Vim, NVim, etc.)

## Installation
Inside the root directory, open your terminal and run `mvn install`:
```
<span style="color: orange;">mvn install</span>
```
Then, run the spring boot app:
```
+ mvn spring-boot:run
```
### SQL Commands
> [!IMPORTANT]
> Before accessing running the command, make sure you have created a database using __pgAdmin__ or access PostgreSQL CLI and run the following command:
```diff
! CREATE DATABASE !<db_name>;
```
Then in pgAdmin or PostgreSQL CLI, run the following SQL statements to insert roles:
```diff
! INSERT INTO <db_name>(roles) VALUES('ROLE_USER');
! INSERT INTO <db_name>(roles) VALUES('ROLE_MODERATOR');
! INSERT INTO <db_name>(roles) VALUES('ROLE_ADMIN');
```

> [! WARNING]
> This application is subject to change as this will be adapted for future changes (e.g., upgrading to a higher Spring Boot, Spring, JDK, and/or Maven versions)
In addition, this project aims to simplify the development of future projects that will utilize Spring Security and JWT. Thus, reducing the development time and focus more on the features of the project and other implementations and/or integrations.
