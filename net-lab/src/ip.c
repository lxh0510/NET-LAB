#include "net.h"
#include "ip.h"
#include "ethernet.h"
#include "arp.h"
#include "icmp.h"

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac)
{
    if(buf->len<sizeof(ip_hdr_t))   return;
    ip_hdr_t *hdr = (ip_hdr_t *)buf->data;
    int examine = (hdr->version == IP_VERSION_4)&&(hdr->hdr_len <= buf->len);
    if(!examine) return;
    uint16_t hdr_checksum16 = hdr->hdr_checksum16;
    hdr->hdr_checksum16 = 0;
    if(checksum16((uint16_t *)buf->data,sizeof(ip_hdr_t)) != hdr_checksum16)  return;
    hdr->hdr_checksum16 = hdr_checksum16;
    if(memcmp(hdr->dst_ip,net_if_ip,NET_IP_LEN)!=0)  return;
    if(buf->len > swap16(hdr->total_len16))
    {
        buf_remove_padding(buf,(buf->len - swap16(hdr->total_len16)));
    }
    if(!((hdr->protocol==NET_PROTOCOL_UDP)||(hdr->protocol==NET_PROTOCOL_ICMP)))
    {
        icmp_unreachable(buf,hdr->src_ip,ICMP_CODE_PROTOCOL_UNREACH);
    }
    buf_remove_header(buf,sizeof(ip_hdr_t));
    net_in(buf,hdr->protocol,hdr->src_ip);
}

/**
 * @brief 处理一个要发送的ip分片
 * 
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf)
{
    buf_add_header(buf,sizeof(ip_hdr_t));
    ip_hdr_t *hdr = (ip_hdr_t *)buf->data;
    hdr->hdr_len = sizeof(ip_hdr_t)/IP_HDR_LEN_PER_BYTE;
    hdr->version = IP_VERSION_4;
    hdr->tos = 0;
    hdr->total_len16 = swap16(buf->len);
    hdr->id16 = swap16(id);
    hdr->flags_fragment16 = swap16((mf == 1)? ((offset >> 3)|IP_MORE_FRAGMENT) : (offset >> 3));
    hdr->ttl = IP_DEFALUT_TTL;
    hdr->protocol = protocol;
    memcpy(hdr->src_ip,net_if_ip,NET_IP_LEN);
    memcpy(hdr->dst_ip,ip,NET_IP_LEN);
    hdr->hdr_checksum16 = 0;
    hdr->hdr_checksum16  = checksum16((uint16_t *)hdr,sizeof(ip_hdr_t));
    arp_out(buf,ip);
}

/**
 * @brief 处理一个要发送的ip数据包
 * 
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol)
{
    buf_t ip_buf;
    static int id = 0;
    size_t mf_size = ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip_hdr_t);
    if(buf->len > mf_size)
    {
        int mf_num = 0;
        while((mf_num + 1)*mf_size < buf->len)
        {
            buf_init(&ip_buf, mf_size);
            memcpy(ip_buf.data,buf->data,mf_size);
            ip_fragment_out(&ip_buf,ip,protocol,id,(uint16_t)(mf_num*mf_size),1);
            mf_num ++;
            buf->data += mf_size;
        }
        int last_mf_size = buf->len - mf_num * mf_size;
        buf_init(&ip_buf, last_mf_size);
        memcpy(ip_buf.data,buf->data,last_mf_size);
        ip_fragment_out(&ip_buf,ip,protocol,id,(uint16_t)(mf_num*mf_size),0);
        id ++;
    }
    else
    {
        buf_init(&ip_buf, buf->len);
        memcpy(ip_buf.data,buf->data,buf->len);
        ip_fragment_out(&ip_buf,ip,protocol,id,0,0);
        id ++;
    }
}

/**
 * @brief 初始化ip协议
 * 
 */
void ip_init()
{
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}