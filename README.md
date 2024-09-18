<div align="center">
 <a href="https://skillicons.dev">
    <img src="https://skillicons.dev/icons?i=java,spring,postgres,docker,kubernetes" />
 </a>
</div>

# Spring Security + JWT (Spring 6.0)
This is the final implementation of Spring Security + JSON Web Tokens (JWT) for authorization and authentication. This will be used as an __integration__ for future projects, and to be configured accordingly based on the requirements.
> [!NOTE]
> If you plan on upgrading JDK version, check the [official documentation](https://spring.io/) for changes in the configurations.
## TODO LIST
### Main Task
- [x] Spring Security 6.0
- [x] JWT (Access / Refresh Tokens)
- [ ] OAuth / Auth 2.0
- [ ] Dockerize
- [ ] K8s (Kubernetes)
### Security Task
- [ ] HTTPS (SSL/TLS Certificate)
- [ ] HashiCorp Vault (For secrets management)
- [ ] Lease Privilege
- [x] Input Validation
- [ ] Rate Limiting
- [ ] OWASP Dependency-Check
- [x] Vulnerability Prevention (e.g., XSS Attack Prevention)
### Misc.
- [ ] Flyway (Version control for database schema)
- [ ] Swagger (OpenAPI)
- [ ] And More...
## Setup Guide
__What you will need:__
+ __Apache Maven__ 3.9.8 or higher ([Apache Maven](https://maven.apache.org/))
+ __JDK__ 17 or higher ([Java](https://www.oracle.com/java/technologies/javase/jdk17-archive-downloads.html))
+ __PostgreSQL__ 14 or higher ([PostgreSQL](https://www.postgresql.org/download/))
+ An IDE of your choice (e.g., [VSCode](https://code.visualstudio.com/download), [Vim](https://www.vim.org/download.php), [NVim](https://neovim.io/), etc.)
## Installation
### Setting up Environment Variables
Inside the root directory, create a .env file and write and save the following:
``` text
DB_USERNAME=
DB_PASSWORD=
JWT_KEY=YOUR_KEY_HERE
JWT_EXPIRATION=
COOKIE=
REFRESH_COOKIE=
REFRESH_TOKEN_EXPIRATION=
DB_NAME=
DB_PORT=
```
Set the values accordingly. If you have node installed, run the command below to generate a random string and paste it in the JWT_KEY in the .env file:
``` sh
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```
### SQL Commands
``` sql
 CREATE DATABASE <db_name>;
```
Then in pgAdmin or PostgreSQL CLI, run the following SQL statements to insert roles:
``` sql
 INSERT INTO <db_name>(roles) VALUES('ROLE_USER');
 INSERT INTO <db_name>(roles) VALUES('ROLE_MODERATOR');
 INSERT INTO <db_name>(roles) VALUES('ROLE_ADMIN');
```
### Maven
> [!IMPORTANT]
> Before running the app, make sure you have created a database using __pgAdmin__ or access PostgreSQL CLI and run the following command:
Open your terminal and run `mvn install`:
``` sh
 mvn install
```
Then, run the spring boot app:
``` sh
 mvn spring-boot:run
```
That's it! Now, test the API endpoints on any API testing software such as Postman.
> [!WARNING]
> This application is subject to change as this will be adapted for future changes (e.g., upgrading to a higher Spring Boot, Spring, JDK, and/or Maven versions)
In addition, this project aims to simplify the development of future projects that will utilize Spring Security and JWT. Thus, reducing the development time and focus more on the features of the project and other implementations and/or integrations.
## References
### Spring Security
- __Spring Security 6.0 + JWT:__ https://youtu.be/oeni_9g7too?si=AT1sZfLET5rT4WDr
- __JWT Refresh Tokens:__ https://youtu.be/nvwKwsJg89E?si=tCDaiM52XnEHaeMu
