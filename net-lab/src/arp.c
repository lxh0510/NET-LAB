#include <string.h>
#include <stdio.h>
#include "net.h"
#include "arp.h"
#include "ethernet.h"
/**
 * @brief 初始的arp包
 * 
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type16 = constswap16(ARP_HW_ETHER),
    .pro_type16 = constswap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = NET_IF_IP,
    .sender_mac = NET_IF_MAC,
    .target_mac = {0}};

/**
 * @brief arp地址转换表，<ip,mac>的容器
 * 
 */
map_t arp_table;

/**
 * @brief arp buffer，<ip,buf_t>的容器
 * 
 */
map_t arp_buf;

/**
 * @brief 打印一条arp表项
 * 
 * @param ip 表项的ip地址
 * @param mac 表项的mac地址
 * @param timestamp 表项的更新时间
 */
void arp_entry_print(void *ip, void *mac, time_t *timestamp)
{
    printf("%s | %s | %s\n", iptos(ip), mactos(mac), timetos(*timestamp));
}

/**
 * @brief 打印整个arp表
 * 
 */
void arp_print()
{
    printf("===ARP TABLE BEGIN===\n");
    map_foreach(&arp_table, arp_entry_print);
    printf("===ARP TABLE  END ===\n");
}

/**
 * @brief 发送一个arp请求
 * 
 * @param target_ip 想要知道的目标的ip地址
 */
void arp_req(uint8_t *target_ip)
{
    buf_init(&txbuf,28);                                                   // 初始化缓冲区 
    arp_pkt_t *hdr = (arp_pkt_t *)txbuf.data;                              // 填写ARP报头
    memcpy(hdr,&arp_init_pkt,sizeof(arp_pkt_t));
    hdr->opcode16 = swap16(ARP_REQUEST);
    memcpy(hdr->target_ip,target_ip,NET_IP_LEN);
    ethernet_out(&txbuf,ether_broadcast_mac,NET_PROTOCOL_ARP);             // 发送报文
}

/**
 * @brief 发送一个arp响应
 * 
 * @param target_ip 目标ip地址
 * @param target_mac 目标mac地址
 */
void arp_resp(uint8_t *target_ip, uint8_t *target_mac)
{
    buf_init(&txbuf,28);
    arp_pkt_t *hdr = (arp_pkt_t *)txbuf.data;
    memcpy(hdr,&arp_init_pkt,sizeof(arp_pkt_t));
    hdr->opcode16 = swap16(ARP_REPLY);
    memcpy(hdr->target_ip,target_ip,NET_IP_LEN);
    memcpy(hdr->target_mac,target_mac,NET_MAC_LEN);
    ethernet_out(&txbuf,target_mac,NET_PROTOCOL_ARP);
}

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void arp_in(buf_t *buf, uint8_t *src_mac)
{
    if(buf->len<sizeof(arp_pkt_t))  return;
    else
    {
        arp_pkt_t *hdr = (arp_pkt_t *)buf->data;
        int examine = (hdr->hw_type16 == constswap16(ARP_HW_ETHER))&&(hdr->pro_type16 == constswap16(NET_PROTOCOL_IP))&&(hdr->hw_len == NET_MAC_LEN)
                            &&(hdr->pro_len == NET_IP_LEN)&&(hdr->opcode16 == swap16(ARP_REQUEST)||hdr->opcode16 == swap16(ARP_REPLY));
        if(!examine)    return;
        map_set(&arp_table,hdr->sender_ip,hdr->sender_mac);
        // 此处一定要加上对操作类型=ARP_REPLY的判断，此处收到的应是应答报文，才进行接下来处理。
        if(map_get(&arp_buf,hdr->sender_ip)!=NULL&&(hdr->opcode16 == swap16(ARP_REPLY)))
        {
            ethernet_out(map_get(&arp_buf,hdr->sender_ip),hdr->sender_mac,NET_PROTOCOL_IP);
            map_delete(&arp_buf,hdr->sender_ip);
        }
        else if((hdr->opcode16 == swap16(ARP_REQUEST))&&(memcmp(hdr->target_ip, net_if_ip, NET_IP_LEN) == 0))      
        {
            arp_resp(hdr->sender_ip,hdr->sender_mac);
        }
    }
}

/**
 * @brief 处理一个要发送的数据包
 * 
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void arp_out(buf_t *buf, uint8_t *ip)
{
    if(map_get(&arp_table,ip)!=NULL)
    {
        // 协议一定要为NET_PROTOCOL_IP
        ethernet_out(buf,map_get(&arp_table,ip),NET_PROTOCOL_IP);
    }
    else
    {
        if(map_get(&arp_buf,ip)!=NULL)
        {
            return;
        }
        else
        {
            map_set(&arp_buf,ip,buf);
            arp_req(ip);
        }
    }
}

/**
 * @brief 初始化arp协议
 * 
 */
void arp_init()
{
    map_init(&arp_table, NET_IP_LEN, NET_MAC_LEN, 0, ARP_TIMEOUT_SEC, NULL);
    map_init(&arp_buf, NET_IP_LEN, sizeof(buf_t), 0, ARP_MIN_INTERVAL, buf_copy);
    net_add_protocol(NET_PROTOCOL_ARP, arp_in);
    arp_req(net_if_ip);
}