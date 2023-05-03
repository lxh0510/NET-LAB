#include "ethernet.h"
#include "utils.h"
#include "driver.h"
#include "arp.h"
#include "ip.h"
/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 */
void ethernet_in(buf_t *buf)
{
    if(buf->len < sizeof(ether_hdr_t))                      // 判断数据帧是否完整
    {
        return;
    }
    ether_hdr_t *hdr = (ether_hdr_t *)buf->data;            // 获得源mac以及协议，并移除包头
    buf_remove_header(buf,sizeof(ether_hdr_t));
    uint8_t *mac = hdr->src;
    uint16_t protocol = swap16(hdr->protocol16);
    net_in(buf,protocol,mac);                               // 向上层发送数据
}
/**
 * @brief 处理一个要发送的数据包
 * 
 * @param buf 要处理的数据包
 * @param mac 目标MAC地址
 * @param protocol 上层协议
 */
void ethernet_out(buf_t *buf, const uint8_t *mac, net_protocol_t protocol)
{
    if(buf->len < 46)                                 // 判断数据长度并进行填充
    {
        buf_add_padding(buf,(46 - buf->len));
    }
    buf_add_header(buf,sizeof(ether_hdr_t));         // 添加包头并填写包头信息
    ether_hdr_t *hdr = (ether_hdr_t *)buf->data;
    memcpy(hdr->dst,mac,NET_MAC_LEN);
    memcpy(hdr->src,net_if_mac,NET_MAC_LEN);
    hdr->protocol16 = swap16(protocol);
    driver_send(buf);                                // 发送数据帧
}

/**
 * @brief 初始化以太网协议
 * 
 */
void ethernet_init()
{
    buf_init(&rxbuf, ETHERNET_MAX_TRANSPORT_UNIT + sizeof(ether_hdr_t));
}

/**
 * @brief 一次以太网轮询
 * 
 */
void ethernet_poll()
{
    if (driver_recv(&rxbuf) > 0)
        ethernet_in(&rxbuf);
}
