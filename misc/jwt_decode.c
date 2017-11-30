// gcc -I$PWD/libjwt/include test.c -L$PWD/libjwt/libjwt/.libs -Wl,-rpath $PWD/libjwt/libjwt/.libs -ljwt -o test
//

#include <stdio.h>
#include <jwt.h>
#include <string.h>
#include <time.h>

int main()
{
    jwt_t* jwt;
    long exp;
    int res;
    time_t seconds;

    const char token[] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE1MTA2Njc1MDMsImlkZW50aXR5Ijo1LCJuYmYiOjE1MTA2Njc1MDMsImV4cCI6MTUxMDc1MzkwM30.vMnyCCcu05XTW4PaIOy2A7o4DMcm7G_S65Z7s0vVnEo";

    unsigned char* key = "myterriblesecret";

    printf("Key length : %zu\n", strlen(key));

    res = jwt_decode(&jwt, token, key, strlen(key));
    printf("Success decode : %d\n", res);
    printf("Content token : %s\n", jwt_dump_str(jwt, 0));

    exp = jwt_get_grant_int(jwt, "exp");
    printf("Exp : %lu \n", exp);
    seconds = time(NULL);
    printf("Current time : %lu \n", (long int)seconds);
    printf("Token has expired : %d \n", (long int)seconds > exp);
    return 0;
}