#include "../mud.h"
#include "../aegis256/aegis256.h"

#include <stdio.h>
#include <poll.h>

int main(int argc, char **argv)
{
    if (argc > 2)
        return -1;

    mud::sockaddress local = {
        .sin = {
            .sin_family = AF_INET,
            .sin_port = htons(20000),
            .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        },
    };
    unsigned char key[] = "0123456789ABCDEF0123456789ABCDEF";
    int aes = 1;

    mud::mud* mud = mud::mud_create(&local, key, &aes);

    if (!mud)
    {
        perror("mud_create");
        return -1;
    }

    unsigned char buf[1500];

    for (;;)
    {
        // mandatory, mud have lot of work to do.
        if (mud_update(mud))
            usleep(100000); // don't use all the cpu

        int r = mud_recv(mud, buf, sizeof(buf));

        if (r == -1)
        {
            if (errno == EAGAIN)
                continue;

            perror("mud_recv");
            return -1;
        }
        if (r)
        {
            buf[r] = 0;
            printf("%s\n", buf);
        }
    }
    mud_delete(mud);

    return 0;
}
