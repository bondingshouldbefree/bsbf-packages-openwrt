#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include "getdevinfo.h"

#define LOG_TAG "RIL-DEV"
#ifdef ANDROID
#include <utils/Log.h>
#endif

const char* devmode2str[] = {"ppp", "ncm", "ecm", "qmi", "ndis"};


#define MAX_PATH 1024
#define MAX_INTF_NAME_LEN 24

#define USBID_LEN 4


#define USB_AT_INF 3
#define USB_PPP_INF 2


#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
extern int (*property_set)(const char *key, const char *value);

struct usb_id_struct {
    unsigned short vid;
    unsigned short pid;
    unsigned short at_inf;
    unsigned short ppp_inf;
};



struct meig_product_info meig_product_list[MEIG_PRODUCT_LIST_SIZE] = {
    {"2dee", "4d07", 2, 3 ,5 , QCM}, //SLM720
//    {"05c6", "f601", 2, 1, 5, QCM}, //SLM630,SLM730,SLM750, SLM868
    {"05c6", "900e", 2, 1, 5, QCM}, //SLM630,SLM730,SLM750, SLM868
    {"05c6", "f601", 1, 2, 5, QCM}, //SLM630,SLM730,SLM750, SLM868
    {"2dee", "4d20", 1, 4, 5, HISI}, //SLM790
    {"2dee", "4d02", 2, 1, 5,  QCM}, //SRM815
    {"2dee", "4d22", 2, 1, 5,  QCM}, //SRM815 rls
    {"2dee", "4d23", 2, 1, 5,  QCM}, //SRM815 rls ECM
    {"05c6", "901f", 2, 1, 5,  QCM}, //SRM815 rls PCIE
};


struct usb_id_struct usb_id_table[] = {
    {0x2DEE, 0x4D07, 2, 3}, //SLM720
    {0x05c6, 0xf601, 2, 1}, //SLM630,SLM730,SLM750, SLM868
    {0x2dee, 0x4d20, 2, 1}, //SLM790
    {0x2dee, 0x4d02, 2, 1}, //SRM815
    {0x2dee, 0x4d07, 2, 1}, //SRM815
};




int is_usb_match(unsigned short vid, unsigned short pid)
{
    size_t i;
    for (i = 0; i < ARRAY_SIZE(usb_id_table); i++) {
        if (vid == usb_id_table[i].vid) {
            if (pid == 0x0000) //donot check pid
                return 1;
            else if (pid == usb_id_table[i].pid)
                return 1;
        }
    }
    return 0;
}


int  find_vendor_index(const char* vid)
{
    size_t index;
    for (index = 0; index < ARRAY_SIZE(meig_product_list); index++) {
        if (0 == strncasecmp(vid,  meig_product_list[index].vid, 4)) {

            return index;
        }
    }
    return -1;
}


int find_product_index(const char* pid)
{
    size_t index;
    for (index = 0; index < ARRAY_SIZE(meig_product_list); index++) {
        if (0 == strncasecmp(pid,  meig_product_list[index].pid, 4)) {
            return index;
        }
    }
    return -1;
}

int find_product_of_vendor_index(const char* vid, const char* pid)
{
    size_t index;
    for (index = 0; index < ARRAY_SIZE(meig_product_list); index++) {
        if ((0 ==  strncasecmp(vid,  meig_product_list[index].vid, 4))  && (0 ==  strncasecmp(pid,  meig_product_list[index].pid, 4)) ) {
            return index;
        }
    }
    return -1;
}


static void dump_net_info(MODEM_INFO* netinfo)
{
    if(NULL == netinfo ) {
        printf("empty netinfo\n");
        return;
    }
    printf("vid:%s\n", netinfo->info.vid);
    printf("pid:%s\n", netinfo->info.pid);
    printf("at port:%d\n", netinfo->info.at_inf);
    printf("ppp port:%d\n", netinfo->info.ppp_inf);
    printf("net port:%d\n", netinfo->info.net_inf);
    printf("solution:%s\n", netinfo->info.sltn_type == QCM?"QCM":"HISI");
#if 0
    printf("net mode:%s\n", devmode2str[netinfo->net_mod]);
    if(NULL != netinfo->if_name) {
        printf("interface:%s\n", netinfo->if_name);
    }
#endif
    if(NULL != netinfo->at_port_name) {
        printf("at port:%s\n", netinfo->at_port_name);
    }
#if 0
    if(NULL != netinfo->modem_port_name) {
        printf("modem port:%s\n", netinfo->modem_port_name);
    }
#endif

}


char* find_ttyUSBX_by_id(const char* subdir)
{
    DIR *tDir = NULL;
    struct dirent* tent = NULL;
    int found_device = 0;

    if ((tDir = opendir(subdir)) == NULL)  {
        printf("Cannot open directory:%s/", subdir);
        return NULL;
    }

    while ((tent= readdir(tDir)) != NULL) {
        if (strncmp(tent->d_name, "ttyUSB", strlen("ttyUSB")) == 0) {
            printf("Find port = %s", tent->d_name);
            found_device = 1;
            break;
        }
    }
    closedir(tDir );
    return (1 == found_device)?tent->d_name:NULL;

}


int  get_netif_name_by_path(const char* dir, char** out_ifname)
{
    DIR *pDir = NULL;
    DIR *pSubDir = NULL;
    char subdir[MAX_PATH];
    struct dirent* ent = NULL;
    struct dirent* subent = NULL;
    int found_netinf = 0;

    if ((pDir = opendir(dir)) == NULL)  {
        printf("Cannot open directory:%s/", dir);
        return -ENODEV;
    }

    while ((ent = readdir(pDir)) != NULL) {
        if (strncmp(ent->d_name, "net", strlen("net")) == 0) {
            strcpy(subdir, dir);
            strcat(subdir, "/net");
            if ((pSubDir = opendir(subdir)) == NULL)  {
                printf("Cannot open directory:%s/", subdir);
                break;
            }
            while ((subent = readdir(pSubDir)) != NULL) {
                if ((strncmp(subent->d_name, "wwan", strlen("wwan")) == 0)
                        || (strncmp(subent->d_name, "eth", strlen("eth")) == 0)
                        || (strncmp(subent->d_name, "usb", strlen("usb")) == 0)) {
                    found_netinf = 1;
                    printf("found net interface, return it");
                    (*out_ifname) = strdup(subent->d_name);
                    break;
                }
            }
            closedir(pSubDir);
        }

    }
    closedir(pDir);
    if(!found_netinf) {
        (*out_ifname) = strdup("ppp0");
        printf("didn't found net interface");
    }

    return found_netinf;

}


NET_MOD get_netif_mode_by_path(const char* dir, const char* usb_class_name)
{
    DIR *pDir = NULL;
    DIR *pSubDir = NULL;
    char subdir[MAX_PATH];
    struct dirent* ent = NULL;
    struct dirent* subent = NULL;
    //int found_device = 0;
    int find_qmichannel = 0;
    NET_MOD net_mode  = RAS_MOD;


//    strncpy(target_dir, dir, strlen(dir));
    if ((pDir = opendir(dir)) == NULL)  {
        printf("Cannot open directory:%s/", dir);
        return -ENODEV;
    }

    while ((ent = readdir(pDir)) != NULL) {
        //dbg_time("%s\n", ent->d_name);

        if ((strlen(ent->d_name) == strlen(usb_class_name) && !strncmp(ent->d_name, usb_class_name, strlen(usb_class_name)))) {
            strcpy(subdir, dir);
            strncat(subdir, "/", strlen("/"));
            strncat(subdir, ent->d_name, strlen(ent->d_name));
            if ((pSubDir = opendir(subdir)) == NULL)  {
                printf("Cannot open directory:%s/", subdir);
                break;
            }
            while ((subent = readdir(pSubDir)) != NULL) {

                if (strncmp(subent->d_name, "cdc-wdm", strlen("cdc-wdm")) == 0) {
                    printf("Find qmichannel = %s", subent->d_name);
                    find_qmichannel = 1;
#if 0
                    snprintf(uevent_path, MAX_PATH, "%s/%s/%s", subdir, subent->d_name, "uevent");
                    fd_uevent = open(uevent_path, O_RDONLY);
                    if (fd_uevent < 0) {
                        printf("Cannot open file:%s, errno = %d(%s)", uevent_path, errno, strerror(errno));
                    } else {
                        snprintf(cdc_nod, MAX_PATH, "/dev/%s", subent->d_name);
                        read(fd_uevent, uevent_buf, CDCWDM_UEVENT_LEN);
                        close(fd_uevent);
                        pmajor = strstr(uevent_buf, "MAJOR");
                        pminor = strstr(uevent_buf, "MINOR");
                        if (pmajor && pminor) {
                            pmajor += sizeof("MAJOR");
                            pminor += sizeof("MINOR");
                            pcr = pmajor;
                            while (0 != strncmp(pcr++, "\n", 1));
                            *(pcr - 1) = 0;
                            pcr = pminor;
                            while (0 != strncmp(pcr++, "\n", 1));
                            *(pcr - 1) = 0;
                            cdc_major = atoi((const char *)pmajor);
                            cdc_minor = atoi((const char *)pminor);
                            if (0 == stat(cdc_nod, &st)) {
                                if (st.st_rdev != (unsigned)MKDEV(cdc_major, cdc_minor)) {
                                    need_newnod = 1;
                                    if (0 != remove(cdc_nod)) {
                                        LOGE("remove %s failed. errno = %d(%s)", cdc_nod, errno, strerror(errno));
                                    }
                                } else {
                                    need_newnod = 0;
                                }
                            } else {
                                need_newnod = 1;
                            }
                            if ((1 == need_newnod) && (0 != mknod(cdc_nod, S_IRUSR | S_IWUSR | S_IFCHR, MKDEV(cdc_major, cdc_minor)))) {
                                printf("mknod for %s failed, MAJOR = %d, MINOR =%d, errno = %d(%s)", cdc_nod, cdc_major,
                                       cdc_minor, errno, strerror(errno));
                            }
                        } else {
                            printf("major or minor get failed, uevent_buf = %s", uevent_buf);
                        }
                    }
#endif
                    break;
                }
            }
            closedir(pSubDir);
        }

        else if (strncmp(ent->d_name, "GobiQMI", strlen("GobiQMI")) == 0) {
            strcpy(subdir, dir);
            strcat(subdir, "/GobiQMI");
            if ((pSubDir = opendir(subdir)) == NULL)  {
                printf("Cannot open directory:%s/", subdir);
                break;
            }
            while ((subent = readdir(pSubDir)) != NULL) {
                if (strncmp(subent->d_name, "qcqmi", strlen("qcqmi")) == 0) {
                    printf("Find qmichannel = %s", subent->d_name);
                    find_qmichannel = 1;
                    net_mode = QMI_MOD;
                    break;
                }
            }
            closedir(pSubDir);
        }
    }
    closedir(pDir);
    return net_mode;

}





int get_modem_info(MODEM_INFO * netinfo)
{
    struct dirent* ent = NULL;
    //struct dirent* subent = NULL;
    DIR *pDir;
    char dir[MAX_PATH], subdir[MAX_PATH];
    char target_dir[MAX_PATH], parent_d_name[12], buffer[20];
    char *port_name = NULL;
    struct utsname  sname;
    int kernel_version;
    int fd;
    //int i;
    int productIndex = -1;
    int found_modem = 0;


#define CDCWDM_UEVENT_LEN 256
#ifndef MKDEV
#define MKDEV(ma,mi) ((ma)<<8 | (mi))
#endif

#if 0
    int fd_uevent = -1;
    char uevent_path[MAX_PATH] = {0};
    char cdc_nod[MAX_PATH] = {0};
    char uevent_buf[CDCWDM_UEVENT_LEN] = {0};
    char *pmajor = NULL;
    DIR *pSubDir;
    char *pminor = NULL;
    int find_qmichannel = 0;
    char *pcr = NULL;
    int cdc_major = 0;
    int cdc_minor = 0;
    struct stat st = {0};
#endif
    //int need_newnod = 0;
    int osmaj, osmin, ospatch;
    char *usb_class_name = NULL;
    //printf("Get modem info\n");


    netinfo->if_name = NULL;
    netinfo->at_port_name= NULL;
    netinfo->modem_port_name= NULL;
    memset(&netinfo->info, 0x0, sizeof(netinfo->info));
    netinfo->net_mod = RAS_MOD;

    /* get the kernel version now, since we are called before sys_init */
    uname(&sname);
    osmaj = osmin = ospatch = 0;
    sscanf(sname.release, "%d.%d.%d", &osmaj, &osmin, &ospatch);
    kernel_version = KVERSION(osmaj, osmin, ospatch);
    if (kernel_version < KVERSION(3, 6, 0)) {
        usb_class_name = "usb";
    } else {
        usb_class_name = "usbmisc";
    }

    strcpy(dir, "/sys/bus/usb/devices");
    if ((pDir = opendir(dir)) == NULL)  {
        printf("Cannot open directory: %s", dir);
        return -ENODEV;
    }

    while ((ent = readdir(pDir)) != NULL) {
        char idVendor[5] = "";
        char idProduct[5] = "";

        sprintf(subdir, "%s/%s/idVendor", dir, ent->d_name);
        fd = open(subdir, O_RDONLY);
        if (fd > 0) {
            read(fd, idVendor, 4);
            close(fd);
            //dbg_time("idVendor = %s\n", idVendor);
            if (find_vendor_index(idVendor) < 0) {
                continue;
            }

        } else {
            continue;
        }

        sprintf(subdir, "%s/%s/idProduct", dir, ent->d_name);
        fd = open(subdir, O_RDONLY);
        if (fd > 0) {
            read(fd, idProduct, 4);
            close(fd);
            //dbg_time("idProduct = %s\n", idProduct);
            if((productIndex = find_product_of_vendor_index(idVendor, idProduct)) < 0) {
                continue;
            }
        } else {
            continue;
        }
        memcpy(&netinfo->info, &meig_product_list[productIndex], sizeof(struct meig_product_info[productIndex]));
        strcpy(parent_d_name, ent->d_name);

        printf("Find idVendor=%s, idProduct=%s, dname=%s\n", idVendor, idProduct, ent->d_name);

        found_modem = 1;
        break;
    }

    if (!found_modem) {
        printf("Cannot find Meig devices\n");
        closedir(pDir);
        return -ENODEV;
    }
    // strncpy(parent_d_name, ent->d_name, strlen(ent->d_name));
    sprintf(target_dir, "%s/%s:1.%d", dir, parent_d_name, meig_product_list[productIndex].at_inf);
    printf("find target dir:%s, dname:%s, at:%d\n", dir, parent_d_name, meig_product_list[productIndex].at_inf);
    if((port_name = find_ttyUSBX_by_id(target_dir)) != NULL) {
        memset(buffer, 0x0, sizeof(buffer));
        sprintf(buffer, "/dev/%s", port_name);
        netinfo->at_port_name = strdup(buffer);
    } else {
        printf("Cannot find at port\n");
        closedir(pDir);
        return -ENODEV;
    }
    printf("Find path=%s, name=%s\n", target_dir, parent_d_name);
    port_name = NULL;
    memset(target_dir, 0x0, sizeof(target_dir));
    sprintf(target_dir, "%s/%s:1.%d", dir, parent_d_name, meig_product_list[productIndex].ppp_inf);
    if((port_name = find_ttyUSBX_by_id(target_dir)) != NULL) {
        memset(buffer, 0x0, sizeof(buffer));
        sprintf(buffer, "/dev/%s", port_name);
        netinfo->modem_port_name = strdup(buffer);
    } else {
        printf("Cannot find modem port\n");
        closedir(pDir);
        return -ENODEV;
    }
    printf("Find path=%s, name=%s\n", target_dir, parent_d_name);

#if 0
    //find net mode
    memset(target_dir, 0x0, sizeof(target_dir));
    sprintf(target_dir, "%s/%s:1.%d", dir, parent_d_name, meig_product_list[productIndex].net_inf);
    printf("Find net mode in path=%s\n", target_dir);
    netinfo->net_mod =  get_netif_mode_by_path(target_dir, usb_class_name);
    //find net interface
    printf("Find net interface in path=%s\n", target_dir);
    (void)get_netif_name_by_path(target_dir, &netinfo->if_name);
#else
    netinfo->if_name = strdup("ppp0");
#endif

    closedir(pDir);


//find net
    if(found_modem) {
        dump_net_info(netinfo);
    }
    return found_modem;
}






