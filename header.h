#include <unistd.h>
#include <cstring>
#include <cstdint>


//Radiotap Header
struct RadioHeader
{
    uint8_t vison;
    uint8_t pad;
    uint16_t len;
    uint32_t flag;
    uint32_t rate;
};

//Deauthentication, Flags
struct Deauthenication
{
    uint16_t field;
    uint16_t dur;
    uint8_t rec[6];
    uint8_t des[6];
    uint8_t bss[6];
    uint16_t num;

};

//Wirelss LAN
struct Wireless
{
    uint16_t code;
};

struct DeauthPacket
{
    struct RadioHeader radio;
    struct Deauthenication deauth;
    struct Wireless wire;
};


