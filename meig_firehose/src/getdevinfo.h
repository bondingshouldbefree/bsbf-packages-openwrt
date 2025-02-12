
/*duanshitao add to get usb device information PID and interface class*/
/*to decide the net mode and at channel and data channel*/
#ifndef __GETDEVINFO_H__
#define __GETDEVINFO_H__


#define KVERSION(j,n,p)    ((j)*1000000 + (n)*1000 + (p))

#define MEIG_PRODUCT_LIST_SIZE  (8)

typedef enum {
    QCM = 0,
    HISI
} SOLUTOIN_TYPE;

typedef enum {
    RAS_MOD = 0,
    NCM_MOD,
    ECM_MOD,
    QMI_MOD,
    NDIS_MOD,
    MAX_MOD
} NET_MOD;

struct meig_product_info {
    char vid[5];
    char pid[5];
    unsigned short at_inf;
    unsigned short ppp_inf;
    unsigned short net_inf;
    SOLUTOIN_TYPE sltn_type;

};

typedef struct {
    struct meig_product_info info;
    char* if_name;
    char* at_port_name;
    char* modem_port_name;
    NET_MOD net_mod;

} MODEM_INFO;

extern const char* devmode2str[];
extern struct meig_product_info meig_product_list[];
int get_modem_info(MODEM_INFO * netinfo);

#endif


